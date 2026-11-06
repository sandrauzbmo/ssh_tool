package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
	"github.com/coder/websocket"
)

func connectionFixture(t *testing.T, handler func(*websocket.Conn, string), options ...*websocket.AcceptOptions) *Agent {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/challenge" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": "fixture-challenge"})
			return
		}
		var opts *websocket.AcceptOptions
		if len(options) > 0 {
			opts = options[0]
		}
		ws, err := websocket.Accept(w, r, opts)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		id := r.Header.Get("X-AgentSSH-Device")
		b, _ := json.Marshal(protocol.Message{Type: "welcome", Version: protocol.Version, DeviceID: id, Generation: "fixture-generation"})
		if err := ws.Write(r.Context(), websocket.MessageText, b); err != nil {
			return
		}
		handler(ws, id)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	id.Registered = true
	id.Server = ts.URL
	if err := SaveIdentity(dir, id); err != nil {
		t.Fatal(err)
	}
	a, err := New(pack.Config{Server: ts.URL, Protocol: protocol.Version}, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	a.Identity, a.HTTP = id, ts.Client()
	a.MetadataProvider = func() protocol.Metadata {
		return protocol.Metadata{Hostname: "fixture", Version: protocol.BuildVersion}
	}
	return a
}

func TestControlSurvivesThirtySecondProxyIdleTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("real heartbeat interval regression")
	}
	var messages atomic.Int32
	var idleExpired atomic.Bool
	a := connectionFixture(t, func(ws *websocket.Conn, _ string) {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, b, err := ws.Read(ctx)
			expired := ctx.Err() == context.DeadlineExceeded
			cancel()
			if err != nil {
				idleExpired.Store(expired)
				return
			}
			messages.Add(1)
			var m protocol.Message
			_ = json.Unmarshal(b, &m)
			if m.Type != "metadata" && m.Type != "heartbeat" {
				return
			}
			b, _ = json.Marshal(protocol.Message{Type: "heartbeat_ack"})
			if err = ws.Write(context.Background(), websocket.MessageText, b); err != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 42*time.Second)
	defer cancel()
	_ = a.connected(ctx, nil)
	if ctx.Err() != context.DeadlineExceeded || idleExpired.Load() || messages.Load() < 3 {
		t.Fatalf("control connection did not survive the idle limit: messages=%d idle_expired=%v", messages.Load(), idleExpired.Load())
	}
}

func TestSuccessfulWelcomeResetsReconnectDelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var welcomes atomic.Int32
	a := connectionFixture(t, func(ws *websocket.Conn, _ string) {
		read, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if _, _, err := ws.Read(read); err != nil {
			return
		}
		if welcomes.Add(1) == 6 {
			cancel()
		}
	})
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if welcomes.Load() < 6 {
		t.Fatalf("reconnect delay accumulated across successful connections: welcomes=%d", welcomes.Load())
	}
}

func TestMissingPongsCloseHalfOpenControlPromptly(t *testing.T) {
	if testing.Short() {
		t.Skip("real dead-peer detection interval regression")
	}
	a := connectionFixture(t, func(ws *websocket.Conn, _ string) {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}, &websocket.AcceptOptions{OnPingReceived: func(context.Context, []byte) bool { return false }})
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	started := time.Now()
	err := a.connected(ctx, nil)
	if err == nil || ctx.Err() != nil || time.Since(started) > 30*time.Second {
		t.Fatal("a half-open connection waited for the application read timeout")
	}
}
