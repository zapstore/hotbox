package nostr

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip46"
)

const (
	defaultSessionUses = 64
	maxSessionUses     = 1024
)

type SessionInfo struct {
	ID            string    `json:"id"`
	URL           string    `json:"url,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	UsesRemaining int       `json:"uses_remaining"`
	BoundClient   string    `json:"bound_client,omitempty"`
}

type capability struct {
	service   *Service
	id        string
	secret    string
	expires   time.Time
	uses      int
	bound     string
	listener  net.Listener
	server    *http.Server
	mu        sync.Mutex
	clients   map[*sessionClient]struct{}
	closed    bool
	exhausted bool
}

type sessionClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
	subs map[string]gonostr.Filters
}

func (s *Service) NewSession(ttl time.Duration, uses int) (SessionInfo, error) {
	if ttl <= 0 || ttl > time.Hour {
		return SessionInfo{}, fmt.Errorf("ttl must be greater than zero and no more than one hour")
	}
	if uses == 0 {
		uses = defaultSessionUses
	}
	if uses < 1 || uses > maxSessionUses {
		return SessionInfo{}, fmt.Errorf("uses must be between 1 and %d", maxSessionUses)
	}
	id, err := randomHex(16)
	if err != nil {
		return SessionInfo{}, err
	}
	secret, err := randomHex(24)
	if err != nil {
		return SessionInfo{}, err
	}
	relayToken, err := randomHex(16)
	if err != nil {
		return SessionInfo{}, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return SessionInfo{}, err
	}
	capability := &capability{
		service:  s,
		id:       id,
		secret:   secret,
		expires:  time.Now().Add(ttl),
		uses:     uses,
		listener: listener,
		clients:  make(map[*sessionClient]struct{}),
	}
	mux := http.NewServeMux()
	relayPath := "/" + relayToken
	mux.HandleFunc(relayPath, capability.serveWS)
	capability.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 << 10,
	}

	s.mu.Lock()
	s.sessions[id] = capability
	s.mu.Unlock()
	go func() { _ = capability.server.Serve(listener) }()
	go func() {
		timer := time.NewTimer(time.Until(capability.expires))
		defer timer.Stop()
		select {
		case <-timer.C:
			s.RevokeSession(id)
		case <-s.ctx.Done():
			s.RevokeSession(id)
		}
	}()

	relayURL := (&url.URL{Scheme: "ws", Host: listener.Addr().String(), Path: relayPath}).String()
	bunkerURL := (&url.URL{Scheme: "bunker", Host: s.pubkey, RawQuery: url.Values{
		"relay":  {relayURL},
		"secret": {secret},
		"perms":  {"sign_event"},
	}.Encode()}).String()
	return SessionInfo{ID: id, URL: bunkerURL, ExpiresAt: capability.expires, UsesRemaining: uses}, nil
}

func (s *Service) ListSessions() []SessionInfo {
	s.mu.Lock()
	sessions := make([]*capability, 0, len(s.sessions))
	for _, capability := range s.sessions {
		sessions = append(sessions, capability)
	}
	s.mu.Unlock()
	result := make([]SessionInfo, 0, len(sessions))
	for _, capability := range sessions {
		if info, ok := capability.info(); ok {
			result = append(result, info)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ExpiresAt.Before(result[j].ExpiresAt) })
	return result
}

func (s *Service) RevokeSession(id string) bool {
	s.mu.Lock()
	capability, ok := s.sessions[id]
	if ok {
		delete(s.sessions, id)
	}
	s.mu.Unlock()
	if ok {
		capability.close()
	}
	return ok
}

func (c *capability) info() (SessionInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return SessionInfo{}, false
	}
	bound := c.bound
	if len(bound) > 12 {
		bound = bound[:12]
	}
	return SessionInfo{
		ID:            c.id,
		ExpiresAt:     c.expires,
		UsesRemaining: c.uses,
		BoundClient:   bound,
	}, true
}

func (c *capability) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.secret = ""
	clients := make([]*sessionClient, 0, len(c.clients))
	for client := range c.clients {
		clients = append(clients, client)
	}
	c.mu.Unlock()
	for _, client := range clients {
		_ = client.conn.Close(websocket.StatusNormalClosure, "session revoked")
	}
	_ = c.server.Close()
}

func (c *capability) serveWS(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	if c.closed || !time.Now().Before(c.expires) {
		c.mu.Unlock()
		http.Error(w, "session unavailable", http.StatusGone)
		return
	}
	c.mu.Unlock()
	connection, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	connection.SetReadLimit(512 << 10)
	client := &sessionClient{conn: connection, subs: make(map[string]gonostr.Filters)}
	c.mu.Lock()
	if len(c.clients) >= 8 {
		c.mu.Unlock()
		_ = connection.Close(websocket.StatusTryAgainLater, "session connection limit reached")
		return
	}
	c.clients[client] = struct{}{}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.clients, client)
		c.mu.Unlock()
		_ = connection.Close(websocket.StatusNormalClosure, "")
	}()

	for {
		var message []json.RawMessage
		if err := wsjson.Read(r.Context(), connection, &message); err != nil {
			return
		}
		if len(message) < 2 {
			continue
		}
		var action string
		_ = json.Unmarshal(message[0], &action)
		switch action {
		case "REQ":
			var id string
			filters, ok := parseSessionFilters(message[2:])
			if json.Unmarshal(message[1], &id) == nil && len(id) <= 128 && ok {
				stored := false
				client.mu.Lock()
				if len(client.subs) < 32 {
					client.subs[id] = filters
					stored = true
				}
				client.mu.Unlock()
				if stored {
					client.write(r.Context(), []any{"EOSE", id})
				} else {
					client.write(r.Context(), []any{"CLOSED", id, "rate-limited: too many subscriptions"})
				}
			}
		case "CLOSE":
			var id string
			if json.Unmarshal(message[1], &id) == nil {
				client.mu.Lock()
				delete(client.subs, id)
				client.mu.Unlock()
			}
		case "EVENT":
			var event gonostr.Event
			if json.Unmarshal(message[1], &event) != nil {
				client.write(r.Context(), []any{"NOTICE", "invalid EVENT payload"})
				continue
			}
			reply, revoke, err := c.handleRequest(r.Context(), event)
			if err != nil {
				client.write(r.Context(), []any{"OK", event.ID, false, relayReason(err)})
				continue
			}
			client.write(r.Context(), []any{"OK", event.ID, true, ""})
			c.broadcast(r.Context(), reply)
			if revoke {
				c.service.RevokeSession(c.id)
				return
			}
		}
	}
}

func (c *capability) handleRequest(ctx context.Context, requestEvent gonostr.Event) (gonostr.Event, bool, error) {
	if requestEvent.Kind != gonostr.KindNostrConnect {
		return gonostr.Event{}, false, fmt.Errorf("unexpected event kind")
	}
	target := requestEvent.Tags.Find("p")
	if len(target) < 2 || target[1] != c.service.pubkey {
		return gonostr.Event{}, false, fmt.Errorf("invalid target pubkey")
	}
	valid, err := requestEvent.CheckSignature()
	if err != nil || !valid {
		return gonostr.Event{}, false, fmt.Errorf("invalid client signature")
	}
	sharedKey, err := nip04.ComputeSharedSecret(requestEvent.PubKey, c.service.keyer.private)
	if err != nil {
		return gonostr.Event{}, false, err
	}
	conversationKey, err := nip44.GenerateConversationKey(requestEvent.PubKey, c.service.keyer.private)
	if err != nil {
		return gonostr.Event{}, false, err
	}
	session := nip46.Session{
		PublicKey:       c.service.pubkey,
		SharedKey:       sharedKey,
		ConversationKey: conversationKey,
	}
	request, err := session.ParseRequest(&requestEvent)
	if err != nil {
		return gonostr.Event{}, false, err
	}

	c.mu.Lock()
	if c.closed || c.exhausted || !time.Now().Before(c.expires) {
		c.mu.Unlock()
		return gonostr.Event{}, false, fmt.Errorf("session expired")
	}
	var result string
	var resultErr error
	revoke := false
	consumeUse := false
	if c.bound == "" {
		if request.Method != "connect" || len(request.Params) < 2 ||
			request.Params[0] != c.service.pubkey ||
			subtle.ConstantTimeCompare([]byte(request.Params[1]), []byte(c.secret)) != 1 {
			c.mu.Unlock()
			return gonostr.Event{}, false, fmt.Errorf("valid connect request required")
		}
		c.bound = requestEvent.PubKey
		c.secret = ""
		result = "ack"
	} else if c.bound != requestEvent.PubKey {
		c.mu.Unlock()
		return gonostr.Event{}, false, fmt.Errorf("session belongs to another client")
	} else {
		switch request.Method {
		case "connect":
			result = "ack"
		case "get_public_key":
			result = c.service.pubkey
		case "ping":
			result = "pong"
		case "sign_event":
			if len(request.Params) != 1 {
				resultErr = fmt.Errorf("wrong number of arguments to sign_event")
				break
			}
			var event gonostr.Event
			if err := json.Unmarshal([]byte(request.Params[0]), &event); err != nil {
				resultErr = fmt.Errorf("decode event: %w", err)
				break
			}
			event.PubKey = c.service.pubkey
			event.ID = ""
			event.Sig = ""
			if err := c.service.keyer.SignEvent(ctx, &event); err != nil {
				resultErr = fmt.Errorf("sign event: %w", err)
				break
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				resultErr = err
				break
			}
			result = string(encoded)
			consumeUse = true
		case "logout":
			result = "ack"
			revoke = true
		default:
			resultErr = fmt.Errorf("method %q is not allowed", request.Method)
		}
	}
	_, responseEvent, err := session.MakeResponse(request.ID, requestEvent.PubKey, result, resultErr)
	if err != nil {
		c.mu.Unlock()
		return gonostr.Event{}, false, err
	}
	if err := responseEvent.Sign(c.service.keyer.private); err != nil {
		c.mu.Unlock()
		return gonostr.Event{}, false, err
	}
	if consumeUse {
		c.uses--
		if c.uses <= 0 {
			c.uses = 0
			c.exhausted = true
			revoke = true
		}
	}
	c.mu.Unlock()
	return responseEvent, revoke, nil
}

func (c *capability) broadcast(ctx context.Context, event gonostr.Event) {
	c.mu.Lock()
	clients := make([]*sessionClient, 0, len(c.clients))
	for client := range c.clients {
		clients = append(clients, client)
	}
	c.mu.Unlock()
	for _, client := range clients {
		client.mu.Lock()
		for id, filters := range client.subs {
			if filters.Match(&event) {
				writeCtx, cancel := context.WithTimeout(ctx, time.Second)
				_ = wsjson.Write(writeCtx, client.conn, []any{"EVENT", id, event})
				cancel()
			}
		}
		client.mu.Unlock()
	}
}

func (client *sessionClient) write(ctx context.Context, message any) {
	client.mu.Lock()
	defer client.mu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = wsjson.Write(writeCtx, client.conn, message)
}

func relayReason(err error) string {
	reason := "error: " + err.Error()
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return reason
}

func parseSessionFilters(raw []json.RawMessage) (gonostr.Filters, bool) {
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

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
