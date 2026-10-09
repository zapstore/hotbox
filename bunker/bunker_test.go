package bunker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip46"
)

func TestBunkerSignsOnLocalRelays(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	secret := testKey(t)
	logged := &lockedBuffer{}
	b := start(t, ctx, secret, slog.New(slog.NewTextHandler(logged, nil)))
	defer b.Close()

	ws, wss := splitRelays(t, b.URL(), b.WSS())
	if err := LocalRelay(ws); err != nil {
		t.Fatal(err)
	}
	if err := LocalRelay(wss); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(b.URL())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "bunker" || parsed.Host != b.PublicKey() || parsed.Query().Get("secret") == "" {
		t.Fatalf("url = %s", b.URL())
	}

	clientKey := gonostr.GeneratePrivateKey()
	client, err := nip46.ConnectBunker(ctx, clientKey, b.URL(), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := client.GetPublicKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pub != b.PublicKey() {
		t.Fatalf("public key = %s", pub)
	}
	event := &gonostr.Event{
		Kind:      1,
		CreatedAt: gonostr.Now(),
		Content:   "offline",
		Tags:      gonostr.Tags{},
		PubKey:    pub,
	}
	event.ID = event.GetID()
	body := event.ID
	if err := client.SignEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if event.ID != body {
		t.Fatalf("sign changed event id")
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		t.Fatalf("signature valid=%v err=%v", valid, err)
	}
	if _, err := client.NIP44Encrypt(ctx, pub, "nope"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("nip44_encrypt error = %v", err)
	}
	relays, err := client.RPC(ctx, "get_relays", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(relays, "relay.zapstore") || !strings.Contains(relays, "127.0.0.1") {
		t.Fatalf("relays = %s", relays)
	}

	other, err := nip46.ConnectBunker(ctx, gonostr.GeneratePrivateKey(), b.URL(), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.GetPublicKey(ctx); err != nil {
		t.Fatal(err)
	}
	wrong, err := nip46.ConnectBunker(ctx, gonostr.GeneratePrivateKey(), wrongSecret(t, b.URL()), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	wrongEvent := &gonostr.Event{Kind: 1, CreatedAt: gonostr.Now(), Content: "anyway", Tags: gonostr.Tags{}, PubKey: pub}
	wrongEvent.ID = wrongEvent.GetID()
	if err := wrong.SignEvent(ctx, wrongEvent); err != nil {
		t.Fatal(err)
	}

	again, err := nip46.ConnectBunker(ctx, clientKey, b.URL(), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.GetPublicKey(ctx); err != nil {
		t.Fatal(err)
	}
	text := logged.String()
	if !strings.Contains(text, "msg=signature") || !strings.Contains(text, "result=signed") || !strings.Contains(text, "msg=connected") {
		t.Fatalf("log = %s", text)
	}
	if strings.Contains(text, hex.EncodeToString(secret[:])) || strings.Contains(text, "bunker://") {
		t.Fatal("log contains key material or the bunker URL")
	}
}

func TestPlainEventIsLogged(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	logged := &lockedBuffer{}
	b := start(t, ctx, testKey(t), slog.New(slog.NewTextHandler(logged, nil)))
	defer b.Close()
	ws, _ := splitRelays(t, b.URL(), b.WSS())
	conn, _, err := websocket.Dial(ctx, ws, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	sk := gonostr.GeneratePrivateKey()
	event := gonostr.Event{Kind: 1, CreatedAt: gonostr.Now(), Content: "secret-body", Tags: gonostr.Tags{}}
	if err := event.Sign(sk); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal([]any{"EVENT", event})
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		t.Fatal(err)
	}
	_, message, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(message), "false") {
		t.Fatalf("reply = %s", message)
	}
	text := logged.String()
	if !strings.Contains(text, "msg=connection") || !strings.Contains(text, "msg=event") || !strings.Contains(text, "result=rejected") {
		t.Fatalf("log = %s", text)
	}
	if strings.Contains(text, "secret-body") {
		t.Fatal("log contains the event content")
	}
}

func TestWSSHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b := start(t, ctx, testKey(t), nil)
	defer b.Close()
	_, wss := splitRelays(t, b.URL(), b.WSS())
	conn, _, err := websocket.Dial(ctx, wss, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	if err := conn.Write(ctx, websocket.MessageText, []byte(`["REQ","sub",{"kinds":[24133],"limit":0}]`)); err != nil {
		t.Fatal(err)
	}
	_, message, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var frame []json.RawMessage
	if err := json.Unmarshal(message, &frame); err != nil {
		t.Fatal(err)
	}
	var kind string
	if len(frame) == 0 || json.Unmarshal(frame[0], &kind) != nil || kind != "EOSE" {
		t.Fatalf("first frame = %s", message)
	}
}

func TestShutdownOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	b := start(t, ctx, testKey(t), nil)
	cancel()
	done := make(chan error, 1)
	go func() { done <- b.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func splitRelays(t *testing.T, wsBunker, wssBunker string) (ws, wss string) {
	t.Helper()
	ws = oneRelay(t, wsBunker, "ws")
	wss = oneRelay(t, wssBunker, "wss")
	return ws, wss
}

func wrongSecret(t *testing.T, bunkerURL string) string {
	t.Helper()
	parsed, err := url.Parse(bunkerURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("secret", hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func oneRelay(t *testing.T, bunkerURL, scheme string) string {
	t.Helper()
	parsed, err := url.Parse(bunkerURL)
	if err != nil {
		t.Fatal(err)
	}
	relays := parsed.Query()["relay"]
	if len(relays) != 1 || !strings.HasPrefix(relays[0], scheme+"://") {
		t.Fatalf("relays = %v, want one %s URL", relays, scheme)
	}
	return relays[0]
}

func TestApproverDeniesSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	secret := testKey(t)
	var connect [32]byte
	var token [16]byte
	if _, err := rand.Read(connect[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	seen := make(chan gonostr.Event, 1)
	logged := &lockedBuffer{}
	b, err := Start(ctx, keyFrom(secret), connect, token, listen(t, "127.0.0.1:0"), listen(t, "127.0.0.1:0"), func(_ context.Context, event gonostr.Event) error {
		seen <- event
		return errors.New("no")
	}, slog.New(slog.NewTextHandler(logged, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	client, err := nip46.ConnectBunker(ctx, gonostr.GeneratePrivateKey(), b.URL(), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{Kind: 1, CreatedAt: gonostr.Now(), Content: "please", Tags: gonostr.Tags{}, PubKey: b.PublicKey()}
	event.ID = event.GetID()
	if err := client.SignEvent(ctx, event); err == nil || !strings.Contains(err.Error(), "signature denied") {
		t.Fatalf("sign error = %v", err)
	}
	if event.Sig != "" {
		t.Fatal("denied event was signed")
	}
	text := logged.String()
	if !strings.Contains(text, "msg=signature") || !strings.Contains(text, "result=denied") {
		t.Fatalf("log = %s", text)
	}
	if strings.Contains(text, "please") || strings.Contains(text, hex.EncodeToString(secret[:])) {
		t.Fatal("log contains the event content or the private key")
	}
	select {
	case got := <-seen:
		if got.Kind != 1 || got.Content != "please" {
			t.Fatalf("prompt saw %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("approver was not called")
	}
}

func TestBunkersUseSeparateKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	a := start(t, ctx, testKey(t), nil)
	defer a.Close()
	b := start(t, ctx, testKey(t), nil)
	defer b.Close()
	if a.PublicKey() == b.PublicKey() || a.URL() == b.URL() {
		t.Fatal("bunkers share an identity")
	}
	client, err := nip46.ConnectBunker(ctx, gonostr.GeneratePrivateKey(), a.URL(), nil, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	event := &gonostr.Event{Kind: 1, CreatedAt: gonostr.Now(), Content: "a", Tags: gonostr.Tags{}, PubKey: a.PublicKey()}
	if err := client.SignEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if event.PubKey != a.PublicKey() || event.PubKey == b.PublicKey() {
		t.Fatalf("signed as %s", event.PubKey)
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid {
		t.Fatalf("signature valid=%v err=%v", valid, err)
	}
}

func TestURLStableAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	secret := testKey(t)
	var connect [32]byte
	var token [16]byte
	connect[0] = 1
	token[0] = 2
	wsLn := listen(t, "127.0.0.1:0")
	wssLn := listen(t, "127.0.0.1:0")
	wsAddr, wssAddr := wsLn.Addr().String(), wssLn.Addr().String()
	first, err := Start(ctx, keyFrom(secret), connect, token, wsLn, wssLn, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wsURL, wssURL := first.URL(), first.WSS()
	first.Close()
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	second, err := Start(ctx, keyFrom(secret), connect, token, listen(t, wsAddr), listen(t, wssAddr), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.URL() != wsURL || second.WSS() != wssURL {
		t.Fatalf("url changed\n first %s\n second %s", wsURL, second.URL())
	}
}

func start(t *testing.T, ctx context.Context, secret [32]byte, log *slog.Logger) *Bunker {
	t.Helper()
	var connect [32]byte
	var token [16]byte
	if _, err := rand.Read(connect[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	b, err := Start(ctx, keyFrom(secret), connect, token, listen(t, "127.0.0.1:0"), listen(t, "127.0.0.1:0"), nil, log)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestStartRequiresKey(t *testing.T) {
	var connect [32]byte
	var token [16]byte
	connect[0] = 1
	token[0] = 2
	_, err := Start(t.Context(), nil, connect, token, listen(t, "127.0.0.1:0"), listen(t, "127.0.0.1:0"), nil, nil)
	if err == nil {
		t.Fatal("accepted a nil key")
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func keyFrom(secret [32]byte) KeyFunc {
	return func(ctx context.Context, fn func(key []byte) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(secret[:])
	}
}

func testKey(t *testing.T) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(gonostr.GeneratePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	copy(secret[:], raw)
	return secret
}
