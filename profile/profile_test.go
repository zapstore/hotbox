package profile_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip46"
	"github.com/zapstore/hotbox/bunker"
	"github.com/zapstore/hotbox/profile"
	"vaultcore/vault"
)

func TestSecretIsOnlyAvailableInsideUse(t *testing.T) {
	ctx := t.Context()
	secret := testSecret(t)
	v, prof, _, _ := createProfile(t, ctx, secret)

	var buf bytes.Buffer
	err := v.Cat(ctx, "profiles/"+prof.Name+"/nsec", &buf)
	if !errors.Is(err, vaultcore.ErrSecret) {
		t.Fatalf("cat nsec: %v", err)
	}
	buf.Reset()
	if err := v.Cat(ctx, "profiles/"+prof.Name+"/bunker", &buf); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatal("bunker entry contains the private key")
	}

	dest := t.TempDir()
	res, err := v.Export(ctx, dest, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 2 || res.Files != 2 {
		t.Fatalf("export files=%d skipped=%d", res.Files, res.Skipped)
	}
	matches, err := filepath.Glob(filepath.Join(dest, "profiles", prof.Name, "nsec"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("export wrote nsec: %v %v", matches, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "profiles", prof.Name, "bunker")); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := v.Cat(ctx, "profiles/"+prof.Name+"/android-key", &buf); !errors.Is(err, vaultcore.ErrSecret) {
		t.Fatalf("cat android key: %v", err)
	}
	buf.Reset()
	if err := v.Cat(ctx, "profiles/"+prof.Name+"/android", &buf); err != nil {
		t.Fatal(err)
	}
	var pkcs8 []byte
	if err := prof.Android.Use(ctx, func(key []byte) error {
		pkcs8 = append([]byte(nil), key...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range pkcs8 {
			pkcs8[i] = 0
		}
	}()
	if bytes.Contains(buf.Bytes(), pkcs8) {
		t.Fatal("android entry contains the private key")
	}

	var signed gonostr.Event
	if err := prof.Key(ctx, func(key []byte) error {
		if !bytes.Equal(key, secret) {
			return errors.New("callback key does not match")
		}
		signed = gonostr.Event{Kind: 1, CreatedAt: 1, Content: "x", Tags: gonostr.Tags{}}
		return signed.Sign(hex.EncodeToString(key))
	}); err != nil {
		t.Fatal(err)
	}
	ok, err := signed.CheckSignature()
	if err != nil || !ok {
		t.Fatalf("signature valid=%v err=%v", ok, err)
	}
	if signed.PubKey == "" || signed.PubKey == hex.EncodeToString(secret) {
		t.Fatal("signature carried the private key")
	}
}

func TestBunkerSignsThroughUse(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	secret := testSecret(t)
	wsLn := listen(t, "127.0.0.1:0")
	wssLn := listen(t, "127.0.0.1:0")

	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.vault")
	keys := filepath.Join(dir, "zapstore.key")
	var connect [32]byte
	var token [16]byte
	connect[0] = 7
	token[0] = 9
	v, prof, err := profile.Create(ctx, path, keys, "zapstore", []byte("correct horse battery"), secret, connect, token, port(t, wsLn), port(t, wssLn), testAndroid(t))
	if err != nil {
		t.Fatal(err)
	}

	b, err := bunker.Start(ctx, prof.Key, prof.Connect, prof.Token, wsLn, wssLn, nil, nil)
	npub := prof.Npub
	wsPort, wssPort := prof.WSPort, prof.WSSPort
	prof.Wipe()
	if err != nil {
		_ = v.Close()
		t.Fatal(err)
	}
	if prof.Connect != [32]byte{} || prof.Token != [16]byte{} || prof.Android.PIN != [32]byte{} {
		t.Fatal("capability remained on the profile")
	}
	prefix, decoded, err := nip19.Decode(npub)
	if err != nil || prefix != "npub" || decoded != b.PublicKey() {
		t.Fatalf("npub %s prefix %s decoded %v err %v, bunker %s", npub, prefix, decoded, err, b.PublicKey())
	}

	client, err := nip46.ConnectBunker(ctx, gonostr.GeneratePrivateKey(), b.URL(), nil, func(string) {})
	if err != nil {
		b.Close()
		_ = v.Close()
		t.Fatal(err)
	}
	pub, err := client.GetPublicKey(ctx)
	if err != nil {
		b.Close()
		_ = v.Close()
		t.Fatal(err)
	}
	if pub != b.PublicKey() {
		t.Fatalf("public key %s", pub)
	}
	event := &gonostr.Event{Kind: 1, CreatedAt: gonostr.Now(), Content: "via use", Tags: gonostr.Tags{}, PubKey: pub}
	if err := client.SignEvent(ctx, event); err != nil {
		b.Close()
		_ = v.Close()
		t.Fatal(err)
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid || event.PubKey != b.PublicKey() {
		t.Fatalf("signed event valid=%v err=%v pub=%s", valid, err, event.PubKey)
	}
	b.Close()
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	again, opened, err := profile.Open(ctx, path, keys, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if opened.Name != "zapstore" || opened.Npub != npub || opened.WSPort != wsPort || opened.WSSPort != wssPort || opened.Connect != connect {
		t.Fatalf("reopen name=%s npub=%s ports=%d,%d", opened.Name, opened.Npub, opened.WSPort, opened.WSSPort)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := profile.Open(ctx, path, keys, []byte("wrong password!!!!")); !errors.Is(err, vaultcore.ErrAuth) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestRejectsExtraProfileAndFile(t *testing.T) {
	ctx := t.Context()
	v, _, path, keys := createProfile(t, ctx, testSecret(t))
	if err := v.Add(ctx, "profiles/other/nsec", bytes.NewReader(bytes.Repeat([]byte{2}, 32)), true); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := profile.Open(ctx, path, keys, []byte("correct horse battery")); err == nil {
		t.Fatal("accepted two profiles")
	}

	file := filepath.Join(t.TempDir(), "old.hotbox")
	if err := os.WriteFile(file, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := profile.Open(ctx, file, keys, []byte("correct horse battery"))
	if !errors.Is(err, vaultcore.ErrAuth) {
		t.Fatalf("legacy file: %v", err)
	}
}

func TestCreateNoAndroid(t *testing.T) {
	ctx := t.Context()
	secret := testSecret(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.vault")
	keys := filepath.Join(dir, "zapstore.key")
	var connect [32]byte
	var token [16]byte
	connect[0] = 5
	token[0] = 6
	v, prof, err := profile.Create(ctx, path, keys, "zapstore", []byte("correct horse battery"), secret, connect, token, 10001, 10002, profile.AndroidKey{})
	if err != nil {
		t.Fatal(err)
	}
	if prof.Android.Use != nil || prof.Npub == "" {
		t.Fatalf("android=%v npub=%s", prof.Android.Use != nil, prof.Npub)
	}
	var buf bytes.Buffer
	if err := v.Cat(ctx, "profiles/zapstore/android", &buf); !errors.Is(err, vaultcore.ErrNotFound) {
		t.Fatalf("android entry: %v", err)
	}
	if err := v.Cat(ctx, "profiles/zapstore/android-key", &buf); !errors.Is(err, vaultcore.ErrNotFound) {
		t.Fatalf("android key: %v", err)
	}
	dest := t.TempDir()
	res, err := v.Export(ctx, dest, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 || res.Files != 1 {
		t.Fatalf("export files=%d skipped=%d", res.Files, res.Skipped)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	again, opened, err := profile.Open(ctx, path, keys, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if opened.Android.Use != nil || opened.Npub != prof.Npub {
		t.Fatalf("reopen android=%v npub=%s", opened.Android.Use != nil, opened.Npub)
	}
}

func TestCreateEmptyPassword(t *testing.T) {
	ctx := t.Context()
	secret := testSecret(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.vault")
	keys := filepath.Join(dir, "zapstore.key")
	var connect [32]byte
	var token [16]byte
	connect[0] = 5
	token[0] = 6
	v, prof, err := profile.Create(ctx, path, keys, "zapstore", []byte{}, secret, connect, token, 10001, 10002, profile.AndroidKey{})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	again, opened, err := profile.Open(ctx, path, keys, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if opened.Npub == "" || opened.Npub != prof.Npub {
		t.Fatalf("npub %s", opened.Npub)
	}
}

func TestCreateNoKeyFile(t *testing.T) {
	ctx := t.Context()
	secret := testSecret(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.vault")
	var connect [32]byte
	var token [16]byte
	connect[0] = 3
	token[0] = 4
	v, prof, err := profile.Create(ctx, path, "", "zapstore", []byte("correct horse battery"), secret, connect, token, 10001, 10002, testAndroid(t), vaultcore.NoKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	ks := v.KeyStorage()
	if ks.Kind != vaultcore.KeyNone || ks.Location != "" || !strings.Contains(ks.BackupAdvice(), "no key file") {
		t.Fatalf("storage %+v advice %q", ks, ks.BackupAdvice())
	}
	if prof.Name != "zapstore" {
		t.Fatalf("name %s", prof.Name)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	again, opened, err := profile.Open(ctx, path, "", []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if opened.Name != "zapstore" || again.KeyStorage().Kind != vaultcore.KeyNone {
		t.Fatalf("reopen name=%s kind=%s", opened.Name, again.KeyStorage().Kind)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

func createProfile(t *testing.T, ctx context.Context, secret []byte) (*vaultcore.Vault, profile.Profile, string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.vault")
	keys := filepath.Join(dir, "zapstore.key")
	var connect [32]byte
	var token [16]byte
	if _, err := rand.Read(connect[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	v, prof, err := profile.Create(ctx, path, keys, "zapstore", []byte("correct horse battery"), secret, connect, token, 10001, 10002, testAndroid(t))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("vault file: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, prof, path, keys
}

func testAndroid(t *testing.T) profile.AndroidKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zapstore"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	copy(pin[:], []byte("0123456789abcdef0123456789abcdef"))
	return profile.AndroidKey{Alias: profile.AndroidAlias, PIN: pin, PKCS8: pkcs8, Certs: [][]byte{der}}
}

func testSecret(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(gonostr.GeneratePrivateKey())
	if err != nil || len(raw) != 32 {
		t.Fatal(err)
	}
	return raw
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func port(t *testing.T, ln net.Listener) uint16 {
	t.Helper()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("not tcp")
	}
	return uint16(addr.Port)
}
