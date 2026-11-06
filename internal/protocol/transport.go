package protocol

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type Stream struct {
	net.Conn
	Done    chan struct{}
	once    sync.Once
	writeMu sync.Mutex
}

func NewStream(ctx context.Context, ws *websocket.Conn) *Stream {
	c := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// NetConn resets this limit; restore it after constructing the adapter.
	ws.SetReadLimit(DataLimit)
	s := &Stream{Conn: c, Done: make(chan struct{})}
	go KeepAlive(ctx, ws, s.Done)
	return s
}

// KeepAlive protects active, otherwise silent terminal channels against proxy
// idle timeouts. A 15-second interval also covers proxies with 30-second idle limits.
func KeepAlive(ctx context.Context, ws *websocket.Conn, closed <-chan struct{}) {
	ticker := time.NewTicker(KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			ping, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := ws.Ping(ping)
			cancel()
			if err != nil {
				ws.CloseNow()
				return
			}
		}
	}
}
func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > DataChunk {
			n = DataChunk
		}
		written, e := s.Conn.Write(p[:n])
		total += written
		p = p[written:]
		if e != nil {
			return total, e
		}
		if written == 0 {
			return total, net.ErrClosed
		}
	}
	return total, nil
}
func (s *Stream) Close() error { e := s.Conn.Close(); s.once.Do(func() { close(s.Done) }); return e }
