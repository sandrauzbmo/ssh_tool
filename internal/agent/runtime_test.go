package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func TestRuntimeEnrollmentHonorsTLSAndCannotChangeLocalPolicy(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/agent/bootstrap" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol": 1, "batch_id": "fixture", "token": "fixture-only", "group": "group", "server": "https://unselected.example", "ca": "untrusted replacement", "auto_user": "root"})
	}))
	defer s.Close()
	c := pack.Config{Server: s.URL + "/prefix", Protocol: 1}
	a, err := New(c, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.bootstrap(context.Background()); err == nil {
		t.Fatal("untrusted bootstrap TLS accepted")
	}
	c.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	a, err = New(c, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Config.Server != c.Server || a.Config.CA != c.CA || a.Config.AutoUser != "" || a.Config.Token != "fixture-only" {
		t.Fatal("remote bootstrap changed console, CA trust or local SSH authorization")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	stored, exists, err := LoadConfig(a.StateDir)
	if err != nil || !exists || stored.Token != "" || stored.BatchID != "" {
		t.Fatal("reused runtime client persisted discovered enrollment credentials")
	}
}

func TestConsoleBindingRejectsReuseAndMigratesKnownLegacyIdentity(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	id.Registered = true
	if err = SaveIdentity(dir, id); err != nil {
		t.Fatal(err)
	}
	if err = CheckServerBinding(dir, "https://console-a.test"); err == nil {
		t.Fatal("unbound registered identity adopted without evidence")
	}
	b, _ := json.Marshal(map[string]string{"device_id": id.ID, "server": "https://console-a.test/"})
	if err = os.WriteFile(filepath.Join(dir, "status.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = BindIdentityServer(dir, id, "https://console-a.test"); err != nil {
		t.Fatal(err)
	}
	before := id.PrivateKey
	if err = CheckServerBinding(dir, "https://console-b.test"); err == nil {
		t.Fatal("identity reuse across consoles accepted")
	}
	loaded, err := LoadIdentity(dir)
	if err != nil || loaded.Server != "https://console-a.test" || loaded.PrivateKey != before {
		t.Fatal("migration or rejected console switch changed identity")
	}
	if err = CheckServerBinding(t.TempDir(), "https://console-b.test"); err != nil {
		t.Fatal("independent console state rejected")
	}
}

func TestServiceUnitKeepsRuntimeServerAndEscapesSpecifiers(t *testing.T) {
	unit, err := ServiceUnit("https://console.test/a%20b/$route", "127.0.0.1:2222")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, `--server "https://console.test/a%%20b/$$route" --ssh-target "127.0.0.1:2222"`) {
		t.Fatal("runtime server was lost or not escaped for systemd")
	}
	if _, err = ServiceUnit("https://console.test/\nExecStart=bad", "127.0.0.1:22"); err == nil {
		t.Fatal("newline accepted in unit")
	}
}

func TestBoundIdentityCannotSendProofToAnotherConsole(t *testing.T) {
	requests := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; http.Error(w, "unexpected", 500) }))
	defer s.Close()
	dir := t.TempDir()
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	id.Server = "https://original-console.test"
	id.Registered = true
	SaveIdentity(dir, id)
	a, err := New(pack.Config{Server: s.URL, Protocol: protocol.Version}, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Run(context.Background()); err == nil {
		t.Fatal("cross-console identity accepted")
	}
	if requests != 0 {
		t.Fatal("authentication request sent to wrong console")
	}
}
