// Package bunker is a loopback NIP-46 signer.
// It listens on 127.0.0.1 with ws and wss and does not dial the network.
// One identity has one bunker URL. Any client that reaches the loopback socket can connect and sign.
// The private key is not stored: each operation receives it from KeyFunc
// and must finish with it before returning.
package bunker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

const (
	maxClients = 8
	maxSubs    = 8
	maxRecent  = 32
	maxSubID   = 128
)

var errDenied = errors.New("signature denied")

// Approver is called before each signature. A nil approver allows it.
// Any error denies the signature.
type Approver func(ctx context.Context, event gonostr.Event) error

// KeyFunc runs fn with the private key. The slice is valid only for the
// call. fn must not retain it.
type KeyFunc func(ctx context.Context, fn func(key []byte) error) error

// Bunker serves one unlocked identity on loopback WebSockets.
// The private key is supplied by KeyFunc for each operation and is not kept.
// The connect secret is part of the bunker URL and is not checked.
// A restart loads the same secret.
type Bunker struct {
	pubkey  string
	use     KeyFunc
	connect *secretPage
	approve Approver
	log     *slog.Logger
	relays  []string
	url     string
	wss     string

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
// use supplies the Nostr private key for each operation and must not be nil.
// connect and token are the stable bunker capability. The caller's connect
// array should be wiped by the caller. approve may be nil.
func Start(ctx context.Context, use KeyFunc, connect [32]byte, token [16]byte, wsLn, wssLn net.Listener, approve Approver, log *slog.Logger) (*Bunker, error) {
	defer wipe32(&connect)
	fail := func(err error) (*Bunker, error) {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return nil, err
	}
	if use == nil {
		return fail(errors.New("signing key is missing"))
	}
	if connect == [32]byte{} || token == [16]byte{} {
		return fail(errors.New("bunker secret is missing"))
	}
	var pubkey string
	if err := use(ctx, func(key []byte) error {
		var err error
		pubkey, err = publicKeyHex(key)
		return err
	}); err != nil {
		return fail(err)
	}
	connectPage, err := newSecretPage(connect)
	if err != nil {
		return fail(err)
	}
	abandon := true
	defer func() {
		if abandon {
			connectPage.destroy()
			_ = wsLn.Close()
			_ = wssLn.Close()
		}
	}()
	cert, err := localCertificate()
	if err != nil {
		return nil, err
	}
	pathToken := hex.EncodeToString(token[:])
	var connectHex [64]byte
	hex.Encode(connectHex[:], connect[:])
	defer clear(connectHex[:])
	wsURL := relayURL("ws", wsLn.Addr(), pathToken)
	wssURL := relayURL("wss", wssLn.Addr(), pathToken)
	for _, relay := range []string{wsURL, wssURL} {
		if err := LocalRelay(relay); err != nil {
			return nil, err
		}
	}
	relays := []string{wsURL, wssURL}
	b := &Bunker{
		pubkey:  pubkey,
		use:     use,
		connect: connectPage,
		approve: approve,
		log:     log,
		relays:  relays,
		url:     bunkerURL(pubkey, string(connectHex[:]), wsURL),
		wss:     bunkerURL(pubkey, string(connectHex[:]), wssURL),
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
	abandon = false
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
		b.mu.Lock()
		b.use = nil
		if b.connect != nil {
			b.connect.destroy()
			b.connect = nil
		}
		b.mu.Unlock()
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

// loopbackOrigins lets a page served from this computer, on any port, open the bunker.
// Other web origins are refused.
var loopbackOrigins = []string{"127.0.0.1", "127.0.0.1:*", "localhost", "localhost:*", "[::1]", "[::1]:*"}

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
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: loopbackOrigins})
	if err != nil {
		return
	}
	connection.SetReadLimit(512 << 10)
	remote := r.RemoteAddr
	c := &client{conn: connection, subs: make(map[string]gonostr.Filters)}
	b.mu.Lock()
	if len(b.clients) >= maxClients {
		b.mu.Unlock()
		b.warn("too many connections", "remote", remote)
		_ = connection.Close(websocket.StatusTryAgainLater, "too many connections")
		return
	}
	b.info("connection", "remote", remote)
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, c)
		b.mu.Unlock()
		b.info("connection closed", "remote", remote)
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
				b.warn("event", "result", "rejected", "err", "invalid EVENT payload")
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
		return b.reject(event, errors.New("unsupported event kind"))
	}
	target := event.Tags.Find("p")
	if len(target) < 2 || target[1] != b.pubkey {
		return b.reject(event, errors.New("invalid target pubkey"))
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		return b.reject(event, errors.New("invalid signature"))
	}
	var shared []byte
	var conversation [32]byte
	err = b.useKey(ctx, func(key []byte) error {
		var keyErr error
		shared, keyErr = nip04Shared(event.PubKey, key)
		if keyErr != nil {
			return keyErr
		}
		conversation, keyErr = nip44Conversation(event.PubKey, key)
		return keyErr
	})
	if err != nil {
		clear(shared)
		wipe32(&conversation)
		return b.reject(event, err)
	}
	defer clear(shared)
	defer wipe32(&conversation)
	session := nip46.Session{
		PublicKey:       b.pubkey,
		SharedKey:       shared,
		ConversationKey: conversation,
	}
	request, err := session.ParseRequest(&event)
	if err != nil {
		return b.reject(event, errors.New("invalid request"))
	}
	result, resultErr := b.dispatch(ctx, event.PubKey, request)
	if resultErr != nil && request.Method != "sign_event" {
		b.warn("request failed", "client", event.PubKey, "method", request.Method, "err", resultErr.Error())
	}
	_, response, err := session.MakeResponse(request.ID, event.PubKey, result, resultErr)
	if err != nil {
		return b.reject(event, err)
	}
	if err := b.useKey(ctx, func(key []byte) error {
		return signNostr(&response, key)
	}); err != nil {
		return b.reject(event, err)
	}
	return response, nil
}

func (b *Bunker) dispatch(ctx context.Context, clientPub string, request nip46.Request) (string, error) {
	b.mu.Lock()
	if request.Method == "sign_event" {
		b.mu.Unlock()
		return b.signRequested(ctx, clientPub, request)
	}
	defer b.mu.Unlock()
	switch request.Method {
	case "connect":
		b.info("connected", "client", clientPub)
		return "ack", nil
	case "logout":
		b.info("logged out", "client", clientPub)
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
	default:
		return "", fmt.Errorf("method %q is not allowed", request.Method)
	}
}

func (b *Bunker) reject(event gonostr.Event, err error) (gonostr.Event, error) {
	b.warn("event", "client", event.PubKey, "kind", event.Kind, "id", event.ID, "result", "rejected", "err", err.Error())
	return gonostr.Event{}, err
}

func (b *Bunker) logSign(client string, event *gonostr.Event, result string, reason error) {
	args := []any{"client", client, "result", result}
	if event != nil {
		id := event.ID
		if id == "" {
			id = event.GetID()
		}
		args = append(args, "kind", event.Kind, "id", id)
	}
	if reason != nil {
		b.warn("signature", append(args, "err", reason.Error())...)
		return
	}
	b.info("signature", args...)
}

func (b *Bunker) info(msg string, args ...any) {
	if b != nil && b.log != nil {
		b.log.Info(msg, args...)
	}
}

func (b *Bunker) warn(msg string, args ...any) {
	if b != nil && b.log != nil {
		b.log.Warn(msg, args...)
	}
}

func (b *Bunker) signRequested(ctx context.Context, clientPub string, request nip46.Request) (string, error) {
	if len(request.Params) != 1 {
		err := errors.New("sign_event requires one event")
		b.logSign(clientPub, nil, "rejected", err)
		return "", err
	}
	var event gonostr.Event
	if err := json.Unmarshal([]byte(request.Params[0]), &event); err != nil {
		err = errors.New("invalid event")
		b.logSign(clientPub, nil, "rejected", err)
		return "", err
	}
	if event.PubKey == "" {
		event.PubKey = b.pubkey
	}
	if event.PubKey != b.pubkey {
		err := errors.New("event pubkey does not match bunker")
		b.logSign(clientPub, &event, "rejected", err)
		return "", err
	}
	if event.ID != "" && event.ID != event.GetID() {
		err := errors.New("event id does not match its body")
		b.logSign(clientPub, &event, "rejected", err)
		return "", err
	}
	if b.approve != nil {
		if err := b.approve(ctx, event); err != nil || ctx.Err() != nil {
			b.logSign(clientPub, &event, "denied", errDenied)
			return "", errDenied
		}
	}
	if err := b.useKey(ctx, func(key []byte) error {
		return signNostr(&event, key)
	}); err != nil {
		err = errors.New("sign event failed")
		b.logSign(clientPub, &event, "rejected", err)
		return "", err
	}
	b.logSign(clientPub, &event, "signed", nil)
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (b *Bunker) useKey(ctx context.Context, fn func(key []byte) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.use == nil {
		return errors.New("bunker is closed")
	}
	// Held across the callback so Close waits out an in-flight signature.
	// The callback must not take b.mu. KeyFunc may take its own lock.
	return b.use(ctx, fn)
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
