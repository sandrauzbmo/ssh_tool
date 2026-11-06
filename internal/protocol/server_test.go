package protocol

import "testing"

func TestNormalizeServerPreservesPrefixAndRejectsUnsafeURLs(t *testing.T) {
	for raw, want := range map[string]string{
		"https://EXAMPLE.test:443/app///":  "https://example.test/app",
		"https://[::1]:443/":               "https://[::1]",
		"https://console.test:8443/agent/": "https://console.test:8443/agent",
	} {
		got, err := NormalizeServer(raw)
		if err != nil || got != want {
			t.Fatalf("normalization: %q %v", got, err)
		}
		if Endpoint(got, "agent/bootstrap", false) != want+"/agent/bootstrap" {
			t.Fatal("base path lost")
		}
	}
	for _, raw := range []string{"", "http://console.test", "wss://console.test", "https://user:secret@console.test", "https://console.test?token=secret", "https://console.test?", "https://console.test#", "https://console.test/#x", "https://console.test:0", "https://console.test:65536", "https://console.test:\n", "https://console.test/path with space"} {
		if _, err := NormalizeServer(raw); err == nil {
			t.Fatalf("invalid console URL accepted: %q", raw)
		}
	}
}
