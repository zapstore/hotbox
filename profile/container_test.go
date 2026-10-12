package profile

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	"vaultcore/vault"
)

func TestOpenDirectoryContainer(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.hotbox")
	keys := filepath.Join(dir, "zapstore.key")
	secret, err := hex.DecodeString(nostr.GeneratePrivateKey())
	if err != nil || len(secret) != 32 {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery")
	v, err := vaultcore.Create(ctx, path, keys, pass)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("directory vault: %v", err)
	}
	var connect [32]byte
	var token [16]byte
	connect[0] = 7
	token[0] = 8
	if err := v.Add(ctx, nsecPath("zapstore"), bytes.NewReader(secret), true); err != nil {
		t.Fatal(err)
	}
	body := encodeBunker(connect, token, 10001, 10002)
	if err := v.Add(ctx, bunkerPath("zapstore"), bytes.NewReader(body), false); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	opened, prof, err := Open(ctx, path, keys, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if prof.Name != "zapstore" || prof.Npub == "" || prof.WSPort != 10001 || prof.WSSPort != 10002 {
		t.Fatalf("name=%s npub=%s ports=%d,%d", prof.Name, prof.Npub, prof.WSPort, prof.WSSPort)
	}
}
