package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestCreateKeystoreKeepsPasswordsOutOfArguments(t *testing.T) {
	javaHome := t.TempDir()
	bin := filepath.Join(javaHome, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case " $* " in
*"store secret"*|*"key secret"*) exit 70 ;;
esac
while [ "$#" -gt 0 ]; do
	case "$1" in
	-keystore) shift; keystore=$1 ;;
	esac
	shift
done
IFS= read -r store
IFS= read -r store_confirm
IFS= read -r key
IFS= read -r key_confirm
[ "$store" = "store secret" ] || exit 71
[ "$store_confirm" = "store secret" ] || exit 72
[ "$key" = "key secret" ] || exit 73
[ "$key_confirm" = "key secret" ] || exit 74
echo "fake keystore" >"$keystore"
`
	keytool := filepath.Join(bin, "keytool")
	if err := os.WriteFile(keytool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_HOME", javaHome)
	got, err := createKeystore(t.Context(), "release", "store secret", "key secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake keystore\n" {
		t.Fatalf("keystore = %q", got)
	}
}

func TestPathWithinWorkspace(t *testing.T) {
	workspace := t.TempDir()
	if !pathWithin(workspace, filepath.Join(workspace, "vault.hotbox")) {
		t.Fatal("workspace vault was not detected")
	}
	if pathWithin(workspace, filepath.Join(filepath.Dir(workspace), "vault.hotbox")) {
		t.Fatal("external vault was treated as inside workspace")
	}
}

func TestDecodeNsec(t *testing.T) {
	hexKey := strings.Repeat("1", 64)
	nsec, err := nip19.EncodePrivateKey(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeNsec(nsec)
	if err != nil {
		t.Fatal(err)
	}
	if got != hexKey {
		t.Fatalf("decoded key = %q, want %q", got, hexKey)
	}
	if _, err := nostr.GetPublicKey(got); err != nil {
		t.Fatalf("decoded key is invalid: %v", err)
	}
}

func TestWriteKeystoreCreatesPrivateFileWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.jks")
	if err := writeKeystore(path, []byte("keystore contents")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("keystore mode = %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(contents); got != "keystore contents" {
		t.Fatalf("keystore contents = %q", got)
	}
	if err := writeKeystore(path, []byte("replacement")); err == nil {
		t.Fatal("writeKeystore overwrote an existing file")
	}
}
