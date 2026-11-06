package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sandrauzbmo/ssh_tool/internal/agent"
	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func TestConsoleMustBeExplicitAndDoesNotUseCompiledFallback(t *testing.T) {
	dir := t.TempDir()
	if _, err := configuration(dir, "", ""); err == nil || !strings.Contains(err.Error(), "--server") {
		t.Fatal("missing runtime server did not fail clearly")
	}
	c, err := configuration(dir, "https://CONSOLE.EXAMPLE:443/path/", "")
	if err != nil || c.Server != "https://console.example/path" || c.Token != "" || c.BatchID != "" {
		t.Fatal("generic configuration contains a deployment or failed normalization")
	}
	if err := agent.SaveConfig(dir, c); err != nil {
		t.Fatal(err)
	}
	if _, err := configuration(dir, "", ""); err == nil {
		t.Fatal("saved configuration silently supplied the required command-line argument")
	}
	if _, err := configuration(dir, "https://other.example/path", ""); err == nil {
		t.Fatal("registration settings were transferred to another console")
	}
}

func TestCommandRequiresServerBeforeStartingOrCreatingIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-state")
	if err := runArgs([]string{"--state-dir", dir}); err == nil || !strings.Contains(err.Error(), "--server") {
		t.Fatal("run without --server did not fail")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("missing --server changed local state")
	}
}

func TestLocalConfigPermissionsAndInvalidCAAreRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := configuration(dir, "https://console.example", ""); err == nil {
		t.Fatal("world-readable local settings accepted")
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := withServer(pack.Config{Protocol: protocol.Version}, "https://console.example", ca); err == nil {
		t.Fatal("invalid CA accepted")
	}
}
