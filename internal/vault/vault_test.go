package vault

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTripHidesSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zapstore.hotbox")
	state := testState(t)
	password := "correct horse battery staple"
	if err := Create(path, password, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(hex.EncodeToString(state.Secret[:]))) ||
		bytes.Contains(raw, []byte(hex.EncodeToString(state.Connect[:]))) {
		t.Fatal("vault file contains secret material")
	}
	opened, err := Open(path, password)
	if err != nil {
		t.Fatal(err)
	}
	if opened != state {
		t.Fatal("opened state does not match")
	}
	if _, err := Open(path, "wrong password!!"); err == nil {
		t.Fatal("wrong password opened the vault")
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, password); err == nil {
		t.Fatal("tampered vault opened")
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zapstore.hotbox")
	state := testState(t)
	if err := Create(path, "correct horse battery staple", state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(path, "another strong password", state); err == nil {
		t.Fatal("Create overwrote an existing vault")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing vault changed after refused overwrite")
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
