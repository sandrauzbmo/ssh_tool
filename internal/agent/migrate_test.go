package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceMigrationPreservesIdentityAndRejectsConflict(t *testing.T) {
	source := filepath.Join(t.TempDir(), "foreground")
	os.Mkdir(source, 0700)
	a, e := LoadIdentity(source)
	if e != nil {
		t.Fatal(e)
	}
	a.Registered = true
	SaveIdentity(source, a)
	dest := filepath.Join(t.TempDir(), "service")
	if e = MigrateState(source, dest, os.Getuid(), os.Getgid()); e != nil {
		t.Fatal(e)
	}
	b, e := LoadIdentity(dest)
	if e != nil || b.ID != a.ID || b.PrivateKey != a.PrivateKey || !b.Registered {
		t.Fatal("service migration changed identity")
	}
	if st, e := os.Stat(filepath.Join(dest, "identity.json")); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("service identity permissions")
	}
	other := filepath.Join(t.TempDir(), "other")
	os.Mkdir(other, 0700)
	c, _ := LoadIdentity(other)
	if e = MigrateState(source, other, os.Getuid(), os.Getgid()); e == nil {
		t.Fatal("overwrote different existing identity")
	}
	after, _ := LoadIdentity(other)
	if c.ID != after.ID {
		t.Fatal("conflicting identity was damaged")
	}
}
