package nostr

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
)

func TestOnlyNgitAndZapstoreEventKindsAreAllowed(t *testing.T) {
	for _, kind := range []int{1617, 1618, 1619, 1621, 1630, 1631, 1632, 1633, 27235, 30617, 30618, 3063, 30063, 30509, 32267} {
		if !allowedKind(kind) {
			t.Fatalf("expected kind %d to be allowed", kind)
		}
	}
	for _, kind := range []int{0, 1, 4, 5, 9735, 24133, 99999} {
		if allowedKind(kind) {
			t.Fatalf("expected kind %d to be denied", kind)
		}
	}
}

func TestParseFiltersPreservesRelayIsolation(t *testing.T) {
	raw := []json.RawMessage{json.RawMessage(`{"kinds":[24133],"#p":["client-a"]}`)}
	filters, ok := parseFilters(raw)
	if !ok {
		t.Fatal("valid filter was rejected")
	}
	for _, test := range []struct {
		name  string
		event gonostr.Event
		match bool
	}{
		{
			name:  "intended client",
			event: gonostr.Event{Kind: 24133, Tags: gonostr.Tags{{"p", "client-a"}}},
			match: true,
		},
		{
			name:  "different client",
			event: gonostr.Event{Kind: 24133, Tags: gonostr.Tags{{"p", "client-b"}}},
			match: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := filters.Match(&test.event); got != test.match {
				t.Fatalf("Match() = %v", got)
			}
		})
	}
}

func TestParseFiltersRejectsEmptySubscription(t *testing.T) {
	if _, ok := parseFilters(nil); ok {
		t.Fatal("empty subscription was accepted")
	}
}

func TestBunkerCapabilityIsSingleUse(t *testing.T) {
	service, err := Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	bunkerURL, err := service.URL(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(bunkerURL)
	if err != nil {
		t.Fatal(err)
	}
	secret := parsed.Query().Get("secret")
	if secret == "" {
		t.Fatal("bunker URL has no secret")
	}
	service.bind("first-client", secret)
	service.bind("second-client", secret)

	service.mu.Lock()
	defer service.mu.Unlock()
	if _, ok := service.authorized["first-client"]; !ok {
		t.Fatal("first client was not authorized")
	}
	if _, ok := service.authorized["second-client"]; ok {
		t.Fatal("single-use secret authorized a second client")
	}
	if _, ok := service.tokens[secret]; ok {
		t.Fatal("used secret remained in token store")
	}
}

func TestPruneRemovesExpiredCapabilities(t *testing.T) {
	service := &Service{
		tokens: map[string]grant{
			"expired": {expires: time.Now().Add(-time.Second)},
		},
		authorized: map[string]grant{
			"expired": {expires: time.Now().Add(-time.Second)},
		},
	}
	service.mu.Lock()
	service.pruneLocked(time.Now())
	service.mu.Unlock()
	if len(service.tokens) != 0 || len(service.authorized) != 0 {
		t.Fatal("expired capabilities were not pruned")
	}
}
