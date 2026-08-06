package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/toolchain"
	"github.com/zapstore/hotbox/internal/vault"
)

func TestGenerateKeepsPasswordOutOfArgumentsAndScopesChildEnvironment(t *testing.T) {
	privateKey := strings.Repeat("1", 64)
	signer, err := hotboxnostr.Start(t.Context(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	event := nostr.Event{
		Kind:      30509,
		CreatedAt: nostr.Now(),
		Tags:      nostr.Tags{{"d", "certificate"}},
	}
	if err := event.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(t.TempDir(), "zsp")
	contents := fmt.Sprintf(`#!/bin/sh
case " $* " in
*" secret password "*) exit 70 ;;
esac
case " $* " in *" --offline "*) ;; *) exit 71 ;; esac
case " $* " in *" --key-alias punch "*) ;; *) exit 76 ;; esac
[ -n "$KEYSTORE_PASSWORD" ] || exit 72
[ "$KEYSTORE_KEY_PASSWORD" = "$KEYSTORE_PASSWORD" ] || exit 73
[ "$KEYSTORE_PASSWORD" != "secret password" ] || exit 77
case "$SIGN_WITH" in bunker://*) ;; *) exit 74 ;; esac
IFS= read -r password
[ "$password" = "$KEYSTORE_PASSWORD" ] || exit 75
printf '%%s\n' '%s'
`, string(encoded))
	if err := os.WriteFile(script, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := toolchain.Validate(script)
	if err != nil {
		t.Fatal(err)
	}
	keytoolScript := filepath.Join(t.TempDir(), "keytool")
	keytoolContents := `#!/bin/sh
IFS= read -r source_store_password < /dev/fd/3
IFS= read -r source_key_password < /dev/fd/4
[ "$source_store_password" = "secret password" ] || exit 80
[ "$source_key_password" = "secret password" ] || exit 83
[ -n "$HOTBOX_TRANSIENT_PASSWORD" ] || exit 81
[ "$HOTBOX_TRANSIENT_PASSWORD" != "$source_store_password" ] || exit 82
source_path=
destination_path=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -srckeystore) source_path=$2; shift 2 ;;
    -destkeystore) destination_path=$2; shift 2 ;;
    *) shift ;;
  esac
done
/bin/cp "$source_path" "$destination_path"
`
	if err := os.WriteFile(keytoolScript, []byte(keytoolContents), 0700); err != nil {
		t.Fatal(err)
	}
	keytoolExecutable, err := toolchain.Validate(keytoolScript)
	if err != nil {
		t.Fatal(err)
	}
	got, err := generate(
		t.Context(),
		executable,
		keytoolExecutable,
		vault.Keystore{Name: "release", Bytes: []byte("keystore"), Aliases: []string{"punch"}},
		"secret password",
		"punch",
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != event.ID {
		t.Fatalf("event id = %q, want %q", got.ID, event.ID)
	}
}

func TestRekeyCreatesOneOperationJKS(t *testing.T) {
	keytool, err := toolchain.Resolve("keytool")
	if err != nil {
		t.Skip("keytool unavailable")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "source.jks")
	destination := filepath.Join(directory, "destination.jks")
	const sourcePassword = "source-password"
	create := toolchain.Command(t.Context(), keytool,
		"-genkeypair", "-storetype", "JKS", "-keystore", source,
		"-alias", "punch", "-keyalg", "RSA", "-keysize", "2048",
		"-validity", "1", "-dname", "CN=Hotbox Test", "-noprompt",
		"-storepass:env", "TEST_JKS_PASSWORD",
		"-keypass:env", "TEST_JKS_PASSWORD",
	)
	create.Env = append(create.Env, "TEST_JKS_PASSWORD="+sourcePassword)
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create JKS: %v: %s", err, output)
	}
	transientPassword, err := rekey(
		t.Context(), keytool, source, destination, "punch", sourcePassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(transientPassword)
	if string(transientPassword) == sourcePassword {
		t.Fatal("rekey reused the vault password")
	}
	verify := toolchain.Command(t.Context(), keytool,
		"-list", "-storetype", "JKS", "-keystore", destination,
		"-alias", "punch", "-storepass:env", "TEST_JKS_PASSWORD",
	)
	verify.Env = append(verify.Env, "TEST_JKS_PASSWORD="+string(transientPassword))
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("verify transient JKS: %v: %s", err, output)
	}
}

func TestGenerateWithInstalledZSP(t *testing.T) {
	zsp, err := toolchain.Resolve("zsp")
	if err != nil {
		t.Skip("zsp unavailable")
	}
	keytool, err := toolchain.Resolve("keytool")
	if err != nil {
		t.Skip("keytool unavailable")
	}
	source := filepath.Join(t.TempDir(), "source.jks")
	const password = "source-password"
	create := toolchain.Command(t.Context(), keytool,
		"-genkeypair", "-storetype", "JKS", "-keystore", source,
		"-alias", "punch", "-keyalg", "RSA", "-keysize", "2048",
		"-validity", "1", "-dname", "CN=Hotbox ZSP Test", "-noprompt",
		"-storepass:env", "TEST_JKS_PASSWORD",
		"-keypass:env", "TEST_JKS_PASSWORD",
	)
	create.Env = append(create.Env, "TEST_JKS_PASSWORD="+password)
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create JKS: %v: %s", err, output)
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hotboxnostr.Start(t.Context(), strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	event, err := generate(
		t.Context(), zsp, keytool,
		vault.Keystore{Name: "release", Bytes: contents, Aliases: []string{"punch"}},
		password, "punch", signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := event.CheckSignature()
	if err != nil || !valid || event.Kind != 30509 {
		t.Fatalf("identity event is invalid: %+v", event)
	}
}
