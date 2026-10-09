package bunker

import (
	"bytes"
	"encoding/hex"
	"testing"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

func TestKeyMaterialMatchesNostr(t *testing.T) {
	sk := gonostr.GeneratePrivateKey()
	raw, err := hex.DecodeString(sk)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := gonostr.GetPublicKey(gonostr.GeneratePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := publicKeyHex(raw)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := gonostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if wantPub != gotPub {
		t.Fatalf("pubkey %s\nwant %s", wantPub, gotPub)
	}

	want04, err := nip04.ComputeSharedSecret(pub, sk)
	if err != nil {
		t.Fatal(err)
	}
	got04, err := nip04Shared(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want04, got04) {
		t.Fatal("nip04 shared secret mismatch")
	}
	want44, err := nip44.GenerateConversationKey(pub, sk)
	if err != nil {
		t.Fatal(err)
	}
	got44, err := nip44Conversation(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	if want44 != got44 {
		t.Fatal("nip44 conversation key mismatch")
	}

	event := &gonostr.Event{Kind: 1, CreatedAt: 1, Content: "offline", Tags: gonostr.Tags{}, PubKey: gotPub}
	other := *event
	if err := event.Sign(sk); err != nil {
		t.Fatal(err)
	}
	if err := signNostr(&other, raw); err != nil {
		t.Fatal(err)
	}
	if event.ID != other.ID || event.Sig != other.Sig || event.PubKey != other.PubKey {
		t.Fatalf("signature mismatch\n got %+v\nwant %+v", other, *event)
	}
}
