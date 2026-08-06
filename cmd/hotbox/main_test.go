package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/zapstore/hotbox/internal/android"
	"github.com/zapstore/hotbox/internal/vault"
)

func TestCreateKeystoreKeepsPasswordsOutOfArguments(t *testing.T) {
	javaHome := t.TempDir()
	bin := filepath.Join(javaHome, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case " $* " in
*"store secret"*) exit 70 ;;
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
[ "$key" = "store secret" ] || exit 73
[ "$key_confirm" = "store secret" ] || exit 74
echo "fake keystore" >"$keystore"
`
	keytool := filepath.Join(bin, "keytool")
	if err := os.WriteFile(keytool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JAVA_HOME", javaHome)
	got, err := createKeystore(t.Context(), "release", "store secret", "test")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake keystore\n" {
		t.Fatalf("keystore = %q", got)
	}
}

func TestResolveVaultArgumentPrefersExistingNamedVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	namedVault := filepath.Join(home, ".hotbox", "test.hotbox")
	if err := os.MkdirAll(filepath.Dir(namedVault), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namedVault, []byte("vault"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveVaultArgument("test")
	if err != nil {
		t.Fatal(err)
	}
	if got != namedVault {
		t.Fatalf("vault path = %q, want %q", got, namedVault)
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

func TestWriteMetadataCreatesPrivateFileWithoutOverwriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.jks.json")
	if err := writeMetadata(path, []byte(`{"aliases":["app"],"npub":"npub1example"}`)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("metadata mode = %o", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "nsec") || strings.Contains(string(contents), "password") {
		t.Fatalf("metadata contains secret fields: %q", contents)
	}
	if err := writeMetadata(path, []byte("{}")); err == nil {
		t.Fatal("writeMetadata overwrote an existing file")
	}
}

func TestSignFixtureWithAndroidToolchain(t *testing.T) {
	if os.Getenv("ANDROID_HOME") == "" && os.Getenv("ANDROID_SDK_ROOT") == "" {
		t.Skip("Android SDK is not configured")
	}
	fixture, err := filepath.Abs(filepath.Join("..", "..", "testdata", "hotbox-unsigned.apk"))
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	input := filepath.Join(workspace, "fixture.apk")
	if err := os.WriteFile(input, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := createKeystore(t.Context(), "fixture", "fixture password", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := certificateAliases(t.Context(), vault.Keystore{
		Name: "release", Bytes: key, Aliases: []string{"fixture"},
	}, "fixture password")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || certificates[0].CertificateDN != "CN=fixture" || certificates[0].CertificateSHA256 == "" {
		t.Fatalf("certificates = %+v", certificates)
	}
	output := filepath.Join(workspace, "signed.apk")
	if err := os.WriteFile(output, []byte("old signed APK"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := android.SignAPK(t.Context(), workspace, input, output, vault.Keystore{
		Name: "release", Bytes: key, Aliases: []string{"fixture"},
	}, "fixture", "fixture password", true)
	if err != nil {
		t.Fatal(err)
	}
	if result.CertificateSHA256 == "" {
		t.Fatal("signed fixture did not report a certificate digest")
	}
}

func TestReplaceEnvironmentScopesBunkerURLToRequestedName(t *testing.T) {
	environment := replaceEnvironment([]string{"PATH=/bin", "SIGN_WITH=stale", "HOME=/tmp"}, "SIGN_WITH", "bunker://fresh")
	if strings.Join(environment, "\n") != "PATH=/bin\nHOME=/tmp\nSIGN_WITH=bunker://fresh" {
		t.Fatalf("environment = %q", environment)
	}
}

func TestValidEnvironmentName(t *testing.T) {
	for name, want := range map[string]bool{
		"SIGN_WITH":  true,
		"BUNKER_2":   true,
		"2BUNKER":    false,
		"BUNKER-URL": false,
		"":           false,
	} {
		if got := validEnvironmentName(name); got != want {
			t.Errorf("validEnvironmentName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestVaultCommonName(t *testing.T) {
	for path, want := range map[string]string{
		"/Users/test/.hotbox/developer.hotbox": "developer",
		"/tmp/release":                         "release",
	} {
		if got := vaultCommonName(path); got != want {
			t.Errorf("vaultCommonName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRelayURLs(t *testing.T) {
	t.Setenv("RELAY_URLS", " wss://one.example, ,wss://two.example ")
	if got := strings.Join(relayURLs(), ","); got != "wss://one.example,wss://two.example" {
		t.Fatalf("relayURLs() = %q", got)
	}
}
