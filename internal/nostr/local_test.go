package nostr

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip46"
)

func TestSignEventAllowsAnyKindAndRejectsSignedInput(t *testing.T) {
	service, err := Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []int{1, 24242, 27235, 99999} {
		event, err := service.SignEvent(t.Context(), gonostr.Event{
			Kind:      kind,
			CreatedAt: gonostr.Now(),
			Content:   "test",
		})
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		valid, err := event.CheckSignature()
		if err != nil || !valid {
			t.Fatalf("kind %d signature is invalid", kind)
		}
		if event.PubKey != service.PublicKey() {
			t.Fatalf("kind %d pubkey = %q", kind, event.PubKey)
		}
	}
	if _, err := service.SignEvent(t.Context(), gonostr.Event{ID: "caller-supplied"}); err == nil {
		t.Fatal("accepted a caller-supplied event id")
	}
}

func TestNIP46SessionSignsAndRevokesAfterUseLimit(t *testing.T) {
	service, err := Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.NewSession(time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	if session.URL == "" || session.ID == "" || session.UsesRemaining != 1 {
		t.Fatalf("session = %+v", session)
	}
	service.mu.Lock()
	capability := service.sessions[session.ID]
	service.mu.Unlock()
	clientKey := gonostr.GeneratePrivateKey()
	conversationKey, err := nip44.GenerateConversationKey(service.PublicKey(), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	sharedKey, err := nip04.ComputeSharedSecret(service.PublicKey(), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientSession := nip46.Session{
		PublicKey: service.PublicKey(), SharedKey: sharedKey, ConversationKey: conversationKey,
	}
	connect := makeNIP46Request(t, clientKey, service.PublicKey(), clientSession, nip46.Request{
		ID: "connect", Method: "connect", Params: []string{service.PublicKey(), capability.secret},
	})
	if _, revoke, err := capability.handleRequest(t.Context(), connect); err != nil || revoke {
		t.Fatalf("connect = revoke %v, err %v", revoke, err)
	}
	unsigned := gonostr.Event{Kind: 77777, CreatedAt: gonostr.Now(), Content: "arbitrary kind"}
	encoded, _ := json.Marshal(unsigned)
	sign := makeNIP46Request(t, clientKey, service.PublicKey(), clientSession, nip46.Request{
		ID: "sign", Method: "sign_event", Params: []string{string(encoded)},
	})
	reply, revoke, err := capability.handleRequest(t.Context(), sign)
	if err != nil || !revoke {
		t.Fatalf("sign = revoke %v, err %v", revoke, err)
	}
	plain, err := nip44.Decrypt(reply.Content, conversationKey)
	if err != nil {
		t.Fatal(err)
	}
	var response nip46.Response
	if err := json.Unmarshal([]byte(plain), &response); err != nil {
		t.Fatal(err)
	}
	var signed gonostr.Event
	if err := json.Unmarshal([]byte(response.Result), &signed); err != nil {
		t.Fatal(err)
	}
	valid, err := signed.CheckSignature()
	if err != nil || !valid || signed.PubKey != service.PublicKey() {
		t.Fatal("NIP-46 returned an invalid signature")
	}
	if _, _, err := capability.handleRequest(t.Context(), sign); err == nil {
		t.Fatal("exhausted session accepted another signature")
	}
	service.RevokeSession(session.ID)
	if sessions := service.ListSessions(); len(sessions) != 0 {
		t.Fatalf("exhausted session remains listed: %+v", sessions)
	}
}

func makeNIP46Request(
	t *testing.T,
	clientKey, target string,
	session nip46.Session,
	request nip46.Request,
) gonostr.Event {
	t.Helper()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	content, err := nip44.Encrypt(string(encoded), session.ConversationKey)
	if err != nil {
		t.Fatal(err)
	}
	event := gonostr.Event{
		Kind: gonostr.KindNostrConnect, CreatedAt: gonostr.Now(),
		Tags: gonostr.Tags{{"p", target}}, Content: content,
	}
	if err := event.Sign(clientKey); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestSessionListRedactsURLAndRevokeIsIdempotent(t *testing.T) {
	service, err := Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.NewSession(time.Minute, 2)
	if err != nil {
		t.Fatal(err)
	}
	listed := service.ListSessions()
	if len(listed) != 1 || listed[0].URL != "" {
		t.Fatalf("listed sessions expose capability: %+v", listed)
	}
	if !service.RevokeSession(session.ID) {
		t.Fatal("first revoke failed")
	}
	if service.RevokeSession(session.ID) {
		t.Fatal("second revoke unexpectedly succeeded")
	}
}

func TestSessionRelayAcknowledgesSubscriptionsAndEvents(t *testing.T) {
	service, err := Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.NewSession(time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(session.URL)
	if err != nil {
		t.Fatal(err)
	}
	connection, _, err := websocket.Dial(t.Context(), parsed.Query().Get("relay"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(websocket.StatusNormalClosure, "")

	clientKey := gonostr.GeneratePrivateKey()
	clientPublicKey, err := gonostr.GetPublicKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	filter := gonostr.Filter{
		Kinds: []int{gonostr.KindNostrConnect},
		Tags:  gonostr.TagMap{"p": []string{clientPublicKey}},
	}
	if err := wsjson.Write(t.Context(), connection, []any{"REQ", "nip46", filter}); err != nil {
		t.Fatal(err)
	}
	var message []json.RawMessage
	if err := wsjson.Read(t.Context(), connection, &message); err != nil {
		t.Fatal(err)
	}
	var action string
	_ = json.Unmarshal(message[0], &action)
	if action != "EOSE" {
		t.Fatalf("subscription response = %s", message[0])
	}

	conversationKey, _ := nip44.GenerateConversationKey(service.PublicKey(), clientKey)
	sharedKey, _ := nip04.ComputeSharedSecret(service.PublicKey(), clientKey)
	connect := makeNIP46Request(t, clientKey, service.PublicKey(), nip46.Session{
		PublicKey: service.PublicKey(), SharedKey: sharedKey, ConversationKey: conversationKey,
	}, nip46.Request{
		ID: "connect", Method: "connect", Params: []string{service.PublicKey(), parsed.Query().Get("secret")},
	})
	if err := wsjson.Write(t.Context(), connection, []any{"EVENT", connect}); err != nil {
		t.Fatal(err)
	}
	message = nil
	if err := wsjson.Read(t.Context(), connection, &message); err != nil {
		t.Fatal(err)
	}
	action = ""
	_ = json.Unmarshal(message[0], &action)
	var accepted bool
	if action != "OK" || len(message) < 4 || json.Unmarshal(message[2], &accepted) != nil || !accepted {
		t.Fatalf("event acknowledgement = %s", message)
	}
	message = nil
	if err := wsjson.Read(t.Context(), connection, &message); err != nil {
		t.Fatal(err)
	}
	action = ""
	_ = json.Unmarshal(message[0], &action)
	if action != "EVENT" {
		t.Fatalf("NIP-46 response = %s", message)
	}
}
