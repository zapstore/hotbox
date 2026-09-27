package bunker

import "testing"

func TestLocalRelay(t *testing.T) {
	allowed := []string{
		"ws://127.0.0.1:1/token",
		"wss://127.0.0.1/token",
		"ws://localhost:9",
		"wss://[::1]:443/token",
	}
	for _, raw := range allowed {
		if err := LocalRelay(raw); err != nil {
			t.Fatalf("LocalRelay(%q) = %v", raw, err)
		}
	}
	rejected := []string{
		"",
		"wss://relay.zapstore.dev",
		"https://127.0.0.1/token",
		"ws://10.0.0.1:1/token",
		"ws://user:pass@127.0.0.1/token",
		"http://localhost/token",
	}
	for _, raw := range rejected {
		if err := LocalRelay(raw); err == nil {
			t.Fatalf("LocalRelay(%q) accepted a non-local relay", raw)
		}
	}
}
