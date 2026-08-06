// Package nostr implements the local-only NIP-46 transport used by Hotbox.
package nostr

import (
	"context"
	"fmt"
	"sync"

	gonostr "github.com/nbd-wtf/go-nostr"
)

type Service struct {
	keyer    localKeyer
	pubkey   string
	ctx      context.Context
	sessions map[string]*capability
	mu       sync.Mutex
}

func Start(ctx context.Context, nsec string) (*Service, error) {
	if nsec == "" {
		return nil, fmt.Errorf("no Nostr key configured")
	}
	publicKey, err := gonostr.GetPublicKey(nsec)
	if err != nil {
		return nil, fmt.Errorf("invalid Nostr key: %w", err)
	}
	service := &Service{
		pubkey:   publicKey,
		ctx:      ctx,
		sessions: make(map[string]*capability),
	}
	user := localKeyer{private: nsec}
	service.keyer = user
	go func() {
		<-ctx.Done()
		service.mu.Lock()
		ids := make([]string, 0, len(service.sessions))
		for id := range service.sessions {
			ids = append(ids, id)
		}
		service.mu.Unlock()
		for _, id := range ids {
			service.RevokeSession(id)
		}
	}()
	return service, nil
}

// PublicKey returns the daemon's public Nostr identity.
func (s *Service) PublicKey() string {
	return s.pubkey
}

type localKeyer struct{ private string }

func (k localKeyer) GetPublicKey(context.Context) (string, error) {
	return gonostr.GetPublicKey(k.private)
}

func (k localKeyer) SignEvent(_ context.Context, event *gonostr.Event) error {
	return event.Sign(k.private)
}

// SignEvent signs one caller-supplied event without exposing a reusable
// capability or the private key.
func (s *Service) SignEvent(ctx context.Context, event gonostr.Event) (gonostr.Event, error) {
	if event.ID != "" || event.Sig != "" {
		return gonostr.Event{}, fmt.Errorf("event id and signature must be empty")
	}
	if event.PubKey != "" && event.PubKey != s.pubkey {
		return gonostr.Event{}, fmt.Errorf("event pubkey does not match Hotbox")
	}
	event.PubKey = s.pubkey
	if err := s.keyer.SignEvent(ctx, &event); err != nil {
		return gonostr.Event{}, fmt.Errorf("sign event: %w", err)
	}
	ok, err := event.CheckSignature()
	if err != nil || !ok {
		return gonostr.Event{}, fmt.Errorf("signed event failed verification")
	}
	return event, nil
}
