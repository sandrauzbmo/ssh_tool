package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sandrauzbmo/ssh_tool/internal/pack"
	"github.com/sandrauzbmo/ssh_tool/internal/protocol"
)

func TestRegistrationMarkersPersistAndRejectInvalidAccountReference(t *testing.T) {
	dir := t.TempDir()
	c := pack.Config{Server: "https://console.example", Protocol: protocol.Version, RegistrationName: "wb-demo-sandbox", CookieAccountID: "account_ref-123"}
	if err := ValidateConfig(c); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(dir, c); err != nil {
		t.Fatal(err)
	}
	saved, exists, err := LoadConfig(dir)
	if err != nil || !exists || saved.RegistrationName != c.RegistrationName || saved.CookieAccountID != c.CookieAccountID {
		t.Fatal("registration markers not preserved")
	}
	c.CookieAccountID = "../other-account"
	if ValidateConfig(c) == nil {
		t.Fatal("invalid account reference accepted")
	}
}

func TestRegistrationMarkersTravelInExistingSignedRegistration(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/agent/challenge" {
			json.NewEncoder(w).Encode(map[string]string{"nonce": "synthetic-challenge"})
			return
		}
		if r.URL.Path != "/agent/register" {
			http.Error(w, "unexpected", 404)
			return
		}
		var request protocol.RegisterRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || !protocol.Verify(request.PublicKey, request.Proof, "register") || request.Metadata.RegistrationName != "wb-demo-sandbox" || request.Metadata.CookieAccountID != "selected-account" {
			http.Error(w, "invalid registration marker", 400)
			return
		}
		json.NewEncoder(w).Encode(protocol.RegisterResponse{DeviceID: request.DeviceID})
	}))
	defer server.Close()
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	a, err := New(pack.Config{Server: server.URL, CA: ca, Protocol: protocol.Version, RegistrationName: "wb-demo-sandbox", CookieAccountID: "selected-account"}, t.TempDir(), "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	a.Identity, err = LoadIdentity(a.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || !a.Identity.Registered {
		t.Fatal("registration marker required extra requests or failed")
	}
}
