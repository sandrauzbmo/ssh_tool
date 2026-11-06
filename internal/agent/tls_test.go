package agent

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func TestTLSRequiresTrustAndRejectsRedirects(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/success", http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	c := pack.Config{Server: s.URL, Protocol: protocol.Version}
	a, err := New(c, t.TempDir(), "127.0.0.1:22")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.post(context.Background(), "success", nil, nil); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	c.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	a, err = New(c, t.TempDir(), "127.0.0.1:22")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.post(context.Background(), "success", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = a.post(context.Background(), "redirect", nil, nil); err == nil {
		t.Fatal("HTTPS registration redirect followed")
	}
}
