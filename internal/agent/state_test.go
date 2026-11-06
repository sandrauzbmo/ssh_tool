package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func TestIdentitySurvivesRestartAndRejectsDuplicateProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	lock, e := Lock(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if other, e := Lock(dir); e == nil {
		other.Close()
		t.Fatal("duplicate process accepted")
	}
	a, e := LoadIdentity(dir)
	if e != nil {
		t.Fatal(e)
	}
	b, e := LoadIdentity(dir)
	if e != nil || a.ID != b.ID || a.PrivateKey != b.PrivateKey {
		t.Fatal("identity changed after restart")
	}
	os.WriteFile(filepath.Join(dir, "identity.json"), []byte("corrupt"), 0600)
	if _, e = LoadIdentity(dir); e == nil {
		t.Fatal("corruption silently reset identity")
	}
}
func TestLoopbackOnlyForwarding(t *testing.T) {
	for _, target := range []string{"127.0.0.1:22", "[::1]:2222"} {
		if e := protocol.ValidateTarget(target); e != nil {
			t.Fatal(e)
		}
	}
	for _, target := range []string{"example.com:22", "10.0.0.1:22", "127.0.0.1:0", "127.0.0.1:70000", "localhost:22"} {
		if e := protocol.ValidateTarget(target); e == nil {
			t.Fatalf("unsafe target accepted %s", target)
		}
	}
}
