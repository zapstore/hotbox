// Package nostr implements the local-only NIP-46 transport used by Hotbox.
package nostr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip46"
)

type Service struct {
	signer     nip46.DynamicSigner
	pubkey     string
	tokens     map[string]grant
	authorized map[string]grant
	mu         sync.Mutex
	clients    map[*client]struct{}
	server     *http.Server
	address    string
}

type grant struct{ expires time.Time }

type client struct {
	conn *websocket.Conn
	mu   sync.Mutex
	subs map[string]gonostr.Filters
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
		pubkey:     publicKey,
		tokens:     make(map[string]grant),
		authorized: make(map[string]grant),
		clients:    make(map[*client]struct{}),
	}
	user := localKeyer{private: nsec}
	service.signer = nip46.NewDynamicSigner(
		func(handler string) (string, error) {
			if handler != service.publicKey() {
				return "", fmt.Errorf("unknown bunker key")
			}
			return nsec, nil
		},
		func(handler string) (gonostr.Keyer, error) {
			if handler != service.publicKey() {
				return nil, fmt.Errorf("unknown bunker key")
			}
			return user, nil
		},
		service.authorizeSigning,
		func(string, string) bool { return false },
		nil,
		nil,
	)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	service.address = listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/", service.serveWS)
	service.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go func() { _ = service.server.Serve(listener) }()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = service.server.Shutdown(shutdownCtx)
	}()
	return service, nil
}

// URL creates a bearer capability accepted only by this local relay.
func (s *Service) URL(ttl time.Duration) (string, error) {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(token)
	s.mu.Lock()
	s.pruneLocked(time.Now())
	s.tokens[secret] = grant{expires: time.Now().Add(ttl)}
	s.mu.Unlock()
	return (&url.URL{Scheme: "bunker", Host: s.pubkey, RawQuery: url.Values{
		"relay":  {"ws://" + s.address},
		"secret": {secret},
	}.Encode()}).String(), nil
}

func (s *Service) publicKey() string {
	return s.pubkey
}

func (s *Service) authorizeSigning(event gonostr.Event, client, _ string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	_, ok := s.authorized[client]
	if !ok {
		delete(s.authorized, client)
		return false
	}
	return allowedKind(event.Kind)
}

func allowedKind(kind int) bool {
	switch kind {
	// NIP-34 / GRASP: patches, PRs, issue/status lifecycle, repository state,
	// and NIP-98 HTTP authentication for a GRASP HTTPS git push.
	case 1617, 1618, 1619, 1621, 1630, 1631, 1632, 1633, 27235, 30617, 30618:
		return true
	// Zapstore: application, release, APK asset, and certificate-link events.
	case 3063, 30063, 30509, 32267:
		return true
	default:
		return false
	}
}

func (s *Service) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(128 << 10)
	c := &client{conn: conn, subs: make(map[string]gonostr.Filters)}
	s.mu.Lock()
	s.clients[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
		_ = conn.Close(websocket.StatusNormalClosure, "")
	}()
	for {
		var msg []json.RawMessage
		if err := wsjson.Read(r.Context(), conn, &msg); err != nil {
			return
		}
		if len(msg) < 2 {
			continue
		}
		var action string
		_ = json.Unmarshal(msg[0], &action)
		switch action {
		case "REQ":
			var id string
			filters, ok := parseFilters(msg[2:])
			if json.Unmarshal(msg[1], &id) == nil && len(id) <= 128 && ok {
				c.mu.Lock()
				if len(c.subs) < 32 {
					c.subs[id] = filters
				}
				c.mu.Unlock()
			}
		case "CLOSE":
			var id string
			if json.Unmarshal(msg[1], &id) == nil {
				c.mu.Lock()
				delete(c.subs, id)
				c.mu.Unlock()
			}
		case "EVENT":
			var event gonostr.Event
			if json.Unmarshal(msg[1], &event) != nil || event.Kind != gonostr.KindNostrConnect {
				continue
			}
			req, _, reply, err := s.signer.HandleRequest(r.Context(), &event)
			if err == nil && req.Method == "connect" && len(req.Params) >= 2 {
				s.bind(event.PubKey, req.Params[1])
			}
			if err == nil {
				s.broadcast(r.Context(), reply)
			}
		}
	}
}

func (s *Service) bind(client, secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneLocked(now)
	grant, ok := s.tokens[secret]
	if !ok {
		return
	}
	delete(s.tokens, secret)
	s.authorized[client] = grant
	slog.Info("bunker capability bound")
}

type localKeyer struct{ private string }

func (k localKeyer) GetPublicKey(context.Context) (string, error) {
	return gonostr.GetPublicKey(k.private)
}

func (k localKeyer) SignEvent(_ context.Context, event *gonostr.Event) error {
	return event.Sign(k.private)
}

func (k localKeyer) Encrypt(_ context.Context, plaintext, recipient string) (string, error) {
	key, err := nip44.GenerateConversationKey(recipient, k.private)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, key)
}

func (k localKeyer) Decrypt(_ context.Context, ciphertext, sender string) (string, error) {
	key, err := nip44.GenerateConversationKey(sender, k.private)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ciphertext, key)
}

func (s *Service) broadcast(ctx context.Context, event gonostr.Event) {
	s.mu.Lock()
	clients := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		c.mu.Lock()
		for id, filters := range c.subs {
			if !filters.Match(&event) {
				continue
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = wsjson.Write(writeCtx, c.conn, []any{"EVENT", id, event})
			cancel()
		}
		c.mu.Unlock()
	}
}

func parseFilters(raw []json.RawMessage) (gonostr.Filters, bool) {
	if len(raw) == 0 || len(raw) > 8 {
		return nil, false
	}
	filters := make(gonostr.Filters, 0, len(raw))
	for _, value := range raw {
		var filter gonostr.Filter
		if err := json.Unmarshal(value, &filter); err != nil {
			return nil, false
		}
		filters = append(filters, filter)
	}
	return filters, true
}

func (s *Service) pruneLocked(now time.Time) {
	for token, grant := range s.tokens {
		if !now.Before(grant.expires) {
			delete(s.tokens, token)
		}
	}
	for client, grant := range s.authorized {
		if !now.Before(grant.expires) {
			delete(s.authorized, client)
		}
	}
}
