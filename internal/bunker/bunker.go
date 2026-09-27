// Package bunker is a loopback NIP-46 signer.
// It listens on 127.0.0.1 with ws and wss and does not dial the network.
// Clients such as zsp use the bunker URL as SIGN_WITH.
package bunker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
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
	maxClients = 8
	maxSubs    = 8
	maxRecent  = 32
	maxSubID   = 128

	// localClientKey is the NIP-46 client key for every loopback caller.
	// The listener is 127.0.0.1, so this key is not a capability. The vault
	// connect secret still authorizes the first connect. Callers must use
	// this key; steroid and zsp keep the same constant.
	localClientKey = "0000000000000000000000000000000000000000000000000000000000000002"
)

var errUnauthorized = errors.New("unauthorized")

// Bunker serves one unlocked identity on loopback WebSockets.
type Bunker struct {
	pubkey string
	key    string
	secret []byte
	client string
	opened bool
	relays []string
	url    string
	wss    string

	mu      sync.Mutex
	clients map[*client]struct{}
	recent  []gonostr.Event
	servers []*http.Server
	once    sync.Once
	exited  chan struct{}
	errs    chan error
}

type client struct {
	conn *websocket.Conn
	mu   sync.Mutex
	subs map[string]gonostr.Filters
}

type relayPolicy struct {
	Read  bool `json:"read"`
	Write bool `json:"write"`
}

// Start serves NIP-46 on the provided loopback listeners.
// secret is the Nostr private key. connect and token are the stable bunker
// capability stored in the vault. The process keeps the key until exit.
func Start(ctx context.Context, secret, connect [32]byte, token [16]byte, wsLn, wssLn net.Listener) (*Bunker, error) {
	fail := func(err error) (*Bunker, error) {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return nil, err
	}
	hexKey := hex.EncodeToString(secret[:])
	pubkey, err := gonostr.GetPublicKey(hexKey)
	if err != nil {
		return fail(fmt.Errorf("invalid Nostr private key: %w", err))
	}
	if connect == [32]byte{} || token == [16]byte{} {
		return fail(errors.New("bunker secret is missing"))
	}
	cert, err := localCertificate()
	if err != nil {
		return fail(err)
	}
	clientPub, err := gonostr.GetPublicKey(localClientKey)
	if err != nil {
		return fail(fmt.Errorf("local client key: %w", err))
	}
	pathToken := hex.EncodeToString(token[:])
	connectSecret := hex.EncodeToString(connect[:])
	wsURL := relayURL("ws", wsLn.Addr(), pathToken)
	wssURL := relayURL("wss", wssLn.Addr(), pathToken)
	for _, relay := range []string{wsURL, wssURL} {
		if err := LocalRelay(relay); err != nil {
			return fail(err)
		}
	}
	relays := []string{wsURL, wssURL}
	b := &Bunker{
		pubkey:  pubkey,
		key:     hexKey,
		secret:  []byte(connectSecret),
		client:  clientPub,
		relays:  relays,
		url:     bunkerURL(pubkey, connectSecret, wsURL),
		wss:     bunkerURL(pubkey, connectSecret, wssURL),
		clients: make(map[*client]struct{}),
		exited:  make(chan struct{}),
		errs:    make(chan error, 2),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+pathToken, b.serveWS)
	b.servers = []*http.Server{
		newServer(ctx, mux),
		newServer(ctx, mux),
	}
	go serve(b, b.servers[0], wsLn)
	go serve(b, b.servers[1], tls.NewListener(wssLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}))
	go func() {
		<-ctx.Done()
		b.Close()
	}()
	return b, nil
}

// PublicKey is the bunker's hex Nostr public key.
func (b *Bunker) PublicKey() string { return b.pubkey }

// URL is the ws:// bunker capability for SIGN_WITH. The certificate on the
// wss listener is ephemeral, so clients that verify TLS use this URL.
func (b *Bunker) URL() string { return b.url }

// WSS is the same capability on the loopback wss listener.
func (b *Bunker) WSS() string { return b.wss }

// Wait blocks until both listeners stop.
func (b *Bunker) Wait() error {
	<-b.exited
	var errs []error
	for range 2 {
		if err := <-b.errs; err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close stops both listeners. It is safe to call more than once.
func (b *Bunker) Close() {
	b.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, server := range b.servers {
			_ = server.Shutdown(ctx)
		}
		close(b.exited)
	})
}

func serve(b *Bunker, server *http.Server, ln net.Listener) {
	b.errs <- server.Serve(ln)
	b.Close()
}

func newServer(ctx context.Context, handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
}

func relayURL(scheme string, addr net.Addr, token string) string {
	return (&url.URL{Scheme: scheme, Host: addr.String(), Path: "/" + token}).String()
}

func bunkerURL(pubkey, secret, relay string) string {
	query := url.Values{}
	query.Set("relay", relay)
	query.Set("secret", secret)
	return (&url.URL{Scheme: "bunker", Host: pubkey, RawQuery: query.Encode()}).String()
}

func (b *Bunker) serveWS(w http.ResponseWriter, r *http.Request) {
	connection, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	connection.SetReadLimit(512 << 10)
	c := &client{conn: connection, subs: make(map[string]gonostr.Filters)}
	b.mu.Lock()
	if len(b.clients) >= maxClients {
		b.mu.Unlock()
		_ = connection.Close(websocket.StatusTryAgainLater, "too many connections")
		return
	}
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, c)
		b.mu.Unlock()
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
		if json.Unmarshal(message[0], &action) != nil {
			continue
		}
		switch action {
		case "REQ":
			var id string
			filters, ok := parseFilters(message[2:])
			if json.Unmarshal(message[1], &id) != nil || len(id) == 0 || len(id) > maxSubID || !ok {
				continue
			}
			c.mu.Lock()
			room := len(c.subs) < maxSubs
			if room {
				c.subs[id] = filters
			}
			c.mu.Unlock()
			if !room {
				c.write(r.Context(), []any{"CLOSED", id, "rate-limited: too many subscriptions"})
				continue
			}
			b.replay(r.Context(), c, id, filters)
		case "CLOSE":
			var id string
			if json.Unmarshal(message[1], &id) == nil {
				c.mu.Lock()
				delete(c.subs, id)
				c.mu.Unlock()
			}
		case "EVENT":
			var event gonostr.Event
			if json.Unmarshal(message[1], &event) != nil || event.ID == "" {
				c.write(r.Context(), []any{"NOTICE", "invalid EVENT payload"})
				continue
			}
			reply, err := b.accept(r.Context(), event)
			if err != nil {
				c.write(r.Context(), []any{"OK", event.ID, false, relayReason(err)})
				continue
			}
			c.write(r.Context(), []any{"OK", event.ID, true, ""})
			b.publish(r.Context(), reply)
		}
	}
}

func (b *Bunker) accept(ctx context.Context, event gonostr.Event) (gonostr.Event, error) {
	if event.Kind != gonostr.KindNostrConnect {
		return gonostr.Event{}, errors.New("unsupported event kind")
	}
	target := event.Tags.Find("p")
	if len(target) < 2 || target[1] != b.pubkey {
		return gonostr.Event{}, errors.New("invalid target pubkey")
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		return gonostr.Event{}, errors.New("invalid signature")
	}
	shared, err := nip04.ComputeSharedSecret(event.PubKey, b.key)
	if err != nil {
		return gonostr.Event{}, err
	}
	conversation, err := nip44.GenerateConversationKey(event.PubKey, b.key)
	if err != nil {
		return gonostr.Event{}, err
	}
	session := nip46.Session{
		PublicKey:       b.pubkey,
		SharedKey:       shared,
		ConversationKey: conversation,
	}
	request, err := session.ParseRequest(&event)
	if err != nil {
		return gonostr.Event{}, errors.New("invalid request")
	}
	result, resultErr := b.dispatch(ctx, event.PubKey, request)
	_, response, err := session.MakeResponse(request.ID, event.PubKey, result, resultErr)
	if err != nil {
		return gonostr.Event{}, err
	}
	if err := response.Sign(b.key); err != nil {
		return gonostr.Event{}, err
	}
	return response, nil
}

func (b *Bunker) dispatch(_ context.Context, clientPub string, request nip46.Request) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.authorize(clientPub, request); err != nil {
		return "", err
	}
	switch request.Method {
	case "connect", "logout":
		return "ack", nil
	case "ping":
		return "pong", nil
	case "get_public_key":
		return b.pubkey, nil
	case "get_relays":
		policy := make(map[string]relayPolicy, len(b.relays))
		for _, relay := range b.relays {
			policy[relay] = relayPolicy{Read: true, Write: true}
		}
		encoded, err := json.Marshal(policy)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	case "sign_event":
		return signEvent(b.pubkey, b.key, request)
	default:
		return "", fmt.Errorf("method %q is not allowed", request.Method)
	}
}

func (b *Bunker) authorize(clientPub string, request nip46.Request) error {
	if subtle.ConstantTimeCompare([]byte(clientPub), []byte(b.client)) != 1 {
		return errUnauthorized
	}
	if b.opened {
		return nil
	}
	if request.Method != "connect" || len(request.Params) < 2 || len(request.Params[1]) > 128 ||
		request.Params[0] != b.pubkey ||
		subtle.ConstantTimeCompare([]byte(request.Params[1]), b.secret) != 1 {
		return errUnauthorized
	}
	b.opened = true
	for i := range b.secret {
		b.secret[i] = 0
	}
	b.secret = nil
	return nil
}

func signEvent(pubkey, key string, request nip46.Request) (string, error) {
	if len(request.Params) != 1 {
		return "", errors.New("sign_event requires one event")
	}
	var event gonostr.Event
	if err := json.Unmarshal([]byte(request.Params[0]), &event); err != nil {
		return "", errors.New("invalid event")
	}
	if event.PubKey == "" {
		event.PubKey = pubkey
	}
	if event.PubKey != pubkey {
		return "", errors.New("event pubkey does not match bunker")
	}
	if event.ID != "" && event.ID != event.GetID() {
		return "", errors.New("event id does not match its body")
	}
	if err := event.Sign(key); err != nil {
		return "", errors.New("sign event failed")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (b *Bunker) publish(ctx context.Context, event gonostr.Event) {
	b.mu.Lock()
	b.recent = append(b.recent, event)
	if len(b.recent) > maxRecent {
		b.recent = append([]gonostr.Event(nil), b.recent[len(b.recent)-maxRecent:]...)
	}
	clients := make([]*client, 0, len(b.clients))
	for c := range b.clients {
		clients = append(clients, c)
	}
	b.mu.Unlock()
	for _, c := range clients {
		c.send(ctx, event)
	}
}

func (b *Bunker) replay(ctx context.Context, c *client, id string, filters gonostr.Filters) {
	b.mu.Lock()
	recent := append([]gonostr.Event(nil), b.recent...)
	b.mu.Unlock()
	for _, event := range recent {
		if match(filters, &event) {
			c.write(ctx, []any{"EVENT", id, event})
		}
	}
	c.write(ctx, []any{"EOSE", id})
}

func (c *client) send(ctx context.Context, event gonostr.Event) {
	c.mu.Lock()
	ids := make([]string, 0, len(c.subs))
	for id, filters := range c.subs {
		if match(filters, &event) {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.write(ctx, []any{"EVENT", id, event})
	}
}

func (c *client) write(ctx context.Context, message any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = wsjson.Write(writeCtx, c.conn, message)
}

func match(filters gonostr.Filters, event *gonostr.Event) bool {
	if len(filters) == 0 {
		return true
	}
	for _, filter := range filters {
		if filter.Matches(event) {
			return true
		}
	}
	return false
}

func parseFilters(raw []json.RawMessage) (gonostr.Filters, bool) {
	if len(raw) == 0 || len(raw) > maxSubs {
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

func relayReason(err error) string {
	reason := "error: " + err.Error()
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return reason
}

func localCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
