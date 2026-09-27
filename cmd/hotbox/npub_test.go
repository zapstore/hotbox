package main

import (
	"encoding/hex"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestNpubFromSecret(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	raw, err := hex.DecodeString(sk)
	if err != nil || len(raw) != 32 {
		t.Fatalf("private key: %v", err)
	}
	var secret [32]byte
	copy(secret[:], raw)
	got, err := npubFromSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	prefix, decoded, err := nip19.Decode(got)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "npub" {
		t.Fatalf("prefix %s", prefix)
	}
	pub, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != pub {
		t.Fatalf("decoded %v, want %s", decoded, pub)
	}
}
