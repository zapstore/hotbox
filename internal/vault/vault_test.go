package vault

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTripHidesSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zapstore.hotbox")
	keyDir := filepath.Join(t.TempDir(), "keys")
	state := testState(t)
	password := []byte("correct horse battery staple")
	keyPath, err := Create(path, keyDir, password, state)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(keyPath) != keyDir {
		t.Fatalf("key file %s is not under %s", keyPath, keyDir)
	}
	for _, p := range []string{path, keyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %o", p, info.Mode().Perm())
		}
	}
	dirInfo, err := os.Stat(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("key dir mode = %o", dirInfo.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(hex.EncodeToString(state.Secret[:]))) ||
		bytes.Contains(raw, []byte(hex.EncodeToString(state.Connect[:]))) ||
		bytes.Contains(raw, keyFile) ||
		bytes.Contains(raw, []byte(hex.EncodeToString(keyFile))) {
		t.Fatal("vault file contains secret material")
	}
	opened, err := Open(path, keyDir, password)
	if err != nil {
		t.Fatal(err)
	}
	if opened != state {
		t.Fatal("opened state does not match")
	}
	if _, err := Open(path, keyDir, []byte("wrong password!!")); err == nil {
		t.Fatal("wrong password opened the vault")
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, keyDir, password); err == nil {
		t.Fatal("tampered vault opened")
	}
}

func TestOpenNeedsKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zapstore.hotbox")
	keyDir := filepath.Join(t.TempDir(), "keys")
	password := []byte("correct horse battery staple")
	keyPath, err := Create(path, keyDir, password, testState(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, t.TempDir(), password); err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("open without key dir: %v", err)
	}
	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyFile[0] ^= 1
	if err := os.WriteFile(keyPath, keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, keyDir, password); err == nil {
		t.Fatal("wrong key file opened the vault")
	}
	if err := os.WriteFile(keyPath, keyFile[:keyFileSize-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, keyDir, password); err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("open with short key file: %v", err)
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zapstore.hotbox")
	keyDir := filepath.Join(t.TempDir(), "keys")
	state := testState(t)
	if _, err := Create(path, keyDir, []byte("correct horse battery staple"), state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	keysBefore, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, keyDir, []byte("another strong password"), state); err == nil {
		t.Fatal("Create overwrote an existing vault")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing vault changed after refused overwrite")
	}
	keysAfter, err := os.ReadDir(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(keysBefore) != 1 || len(keysAfter) != 1 {
		t.Fatalf("key files before=%d after=%d, want 1 and 1", len(keysBefore), len(keysAfter))
	}
}

func TestOpenRejectsVersionOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.hotbox")
	old := `{"version":1,"kdf":{"salt":"AAAAAAAAAAAAAAAAAAAAAA==","time":3,"memory":65536,"threads":4},"wrap":"AA==","data":"AA=="}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path, t.TempDir(), []byte("correct horse battery staple"))
	if err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("open v1 vault: %v", err)
	}
}

func testState(t *testing.T) State {
	t.Helper()
	state := State{Secret: testSecret(t), WSPort: 17431, WSSPort: 17432}
	state.Connect[0] = 9
	state.Token[0] = 8
	return state
}

func testSecret(t *testing.T) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	copy(secret[:], raw)
	return secret
}
