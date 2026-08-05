package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadAndRejectWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	input := testData()
	if err := Save(path, "correct horse battery staple", input); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(loaded.Keystores["release"].Bytes); got != "not-a-real-keystore" {
		t.Fatalf("loaded bytes = %q", got)
	}
	if _, err := Load(path, "wrong"); err == nil {
		t.Fatal("wrong password unexpectedly opened vault")
	}
}

func TestDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := Save(path, "a secure password", testData()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "a secure password"); err == nil {
		t.Fatal("tampered vault unexpectedly opened")
	}
}

func TestSaveRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := Save(path, "first password", testData()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, "second password", testData()); err == nil {
		t.Fatal("Save overwrote an existing vault")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("existing vault changed after refused overwrite")
	}
}

func TestLoadRejectsOversizedVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxVaultFileSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "password"); err == nil {
		t.Fatal("Load accepted an oversized vault")
	}
}

func TestSaveRejectsWeakPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := Save(path, "short", testData()); err == nil {
		t.Fatal("Save accepted a weak password")
	}
}

func testData() Data {
	data := New()
	data.NostrKey = strings.Repeat("1", 64)
	data.Keystores["release"] = Keystore{
		Name: "release", Bytes: []byte("not-a-real-keystore"),
		StorePass: "store", KeyAlias: "app", KeyPass: "key",
	}
	return data
}
