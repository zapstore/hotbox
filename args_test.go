package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/zapstore/hotbox/profile"
	"vaultcore/vault"
)

func TestVersionRequested(t *testing.T) {
	if !versionRequested([]string{"--version"}) || !versionRequested([]string{"--version", "extra"}) {
		t.Fatal("expected --version as the first argument")
	}
	if versionRequested(nil) || versionRequested([]string{"--help"}) || versionRequested([]string{"vault", "--version"}) {
		t.Fatal("version flag only leads the arguments")
	}
}

func TestParseArgs(t *testing.T) {
	vaults, createKey, help, err := parseArgs([]string{"/tmp/a.vault", "/tmp/b.vault"})
	if err != nil {
		t.Fatal(err)
	}
	if help || createKey != "" || len(vaults) != 2 || vaults[0].arg != "/tmp/a.vault" || vaults[0].key != "" {
		t.Fatalf("vaults=%v createKey=%s help=%v", vaults, createKey, help)
	}
	if _, _, help, err := parseArgs([]string{"--help"}); err != nil || !help {
		t.Fatalf("help err=%v help=%v", err, help)
	}
	if _, _, _, err := parseArgs([]string{"--prompt"}); err == nil {
		t.Fatal("accepted --prompt")
	}
	if _, _, _, err := parseArgs([]string{"--nope"}); err == nil {
		t.Fatal("accepted unknown flag")
	}
	vaults, _, _, err = parseArgs([]string{"--key", "/tmp/a.key", "a", "b", "--key", "/tmp/b.key", "c"})
	if err != nil || len(vaults) != 3 || vaults[0].key != "/tmp/a.key" || vaults[1].key != "" || vaults[2].key != "/tmp/b.key" {
		t.Fatalf("vaults=%v err=%v", vaults, err)
	}
	_, createKey, _, err = parseArgs([]string{"--key", "/tmp/new.key"})
	if err != nil || createKey != "/tmp/new.key" {
		t.Fatalf("create key %s err %v", createKey, err)
	}
	if _, _, _, err := parseArgs([]string{"a", "--key", "/tmp/a.key"}); err == nil {
		t.Fatal("accepted a trailing --key")
	}
}

func TestSecretFromInput(t *testing.T) {
	if err := validNsec(""); err != nil {
		t.Fatal(err)
	}
	if err := validNsec("nope"); err == nil {
		t.Fatal("accepted an invalid nsec")
	}
	first, err := secretFromInput("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(first[:]) })
	second, err := secretFromInput("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(second[:]) })
	if first == ([32]byte{}) || first == second {
		t.Fatal("generated key is empty or repeated")
	}
	npub, err := npubFromSecret(first[:])
	if err != nil {
		t.Fatal(err)
	}
	prefix, decoded, err := nip19.Decode(npub)
	if err != nil || prefix != "npub" {
		t.Fatalf("npub %s prefix %s err %v", npub, prefix, err)
	}
	pub, err := nostr.GetPublicKey(hex.EncodeToString(first[:]))
	if err != nil || decoded != pub {
		t.Fatalf("npub %s decoded %v pub %s err %v", npub, decoded, pub, err)
	}
	hexKey := nostr.GeneratePrivateKey()
	got, err := secretFromInput(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(got[:]) })
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], raw) {
		t.Fatal("did not keep the given key")
	}
}

func TestVaultPath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := vaultPath("zapstore")
	if err != nil || got != filepath.Join(cwd, "zapstore.hotbox") {
		t.Fatalf("path %s err %v", got, err)
	}
	got, err = vaultPath("/tmp/zapstore.hotbox")
	if err != nil || got != "/tmp/zapstore.hotbox" {
		t.Fatalf("path %s err %v", got, err)
	}
	got, err = vaultPath("/tmp/zapstore.hotbox/")
	if err != nil || got != "/tmp/zapstore.hotbox" {
		t.Fatalf("trailing slash %s err %v", got, err)
	}
	home, err := vaultPath("~/vaults/zapstore")
	if err != nil || !strings.HasSuffix(home, "/vaults/zapstore.hotbox") {
		t.Fatalf("tilde path %s err %v", home, err)
	}
}

func TestResolvePath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolvePath("zapstore")
	if err != nil || got != filepath.Join(cwd, "zapstore") {
		t.Fatalf("path %s err %v", got, err)
	}
	got, err = resolvePath("keys/zapstore.vault")
	if err != nil || got != filepath.Join(cwd, "keys", "zapstore.vault") {
		t.Fatalf("path %s err %v", got, err)
	}
	got, err = resolvePath("/tmp/zapstore.vault")
	if err != nil || got != "/tmp/zapstore.vault" {
		t.Fatalf("path %s err %v", got, err)
	}
	home, err := resolvePath("~/vaults/zapstore.vault")
	if err != nil || home == "~/vaults/zapstore.vault" || home[0] != '/' {
		t.Fatalf("tilde path %s err %v", home, err)
	}
}

func TestKeyDir(t *testing.T) {
	t.Setenv(keyDirEnv, "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	got, err := keyDir()
	if err != nil || got != filepath.Join(home, ".keys", "hotbox") {
		t.Fatalf("default key dir %s err %v", got, err)
	}
	t.Setenv(keyDirEnv, "~/hotbox-keys")
	got, err = keyDir()
	if err != nil || got[0] != '/' || filepath.Base(got) != "hotbox-keys" {
		t.Fatalf("env key dir %s err %v", got, err)
	}
}

func TestCreateKeyArgs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyDirEnv, dir)
	vault := filepath.Join(dir, "zapstore.hotbox")

	path, opts, err := createKeyArgs(noneChoice, "", vault)
	if err != nil || path != "" || len(opts) != 1 {
		t.Fatalf("none path=%q opts=%d err=%v", path, len(opts), err)
	}
	if _, _, err := createKeyArgs(keychainChoice, filepath.Join(dir, "a.key"), vault); err == nil {
		t.Fatal("accepted --key with the keychain")
	}
	if _, _, err := createKeyArgs(noneChoice, filepath.Join(dir, "a.key"), vault); err == nil {
		t.Fatal("accepted --key with no key file")
	}
	path, opts, err = createKeyArgs(fileChoice, filepath.Join(dir, "a.key"), vault)
	if err != nil || path != filepath.Join(dir, "a.key") || len(opts) != 0 {
		t.Fatalf("file path=%q opts=%d err=%v", path, len(opts), err)
	}
	path, opts, err = createKeyArgs(fileChoice, "", vault)
	if err != nil || path != filepath.Join(dir, "zapstore.key") || len(opts) != 0 {
		t.Fatalf("default file path=%q opts=%d err=%v", path, len(opts), err)
	}
	if _, _, err := createKeyArgs("elsewhere", "", vault); err == nil {
		t.Fatal("accepted an unknown choice")
	}
}

func TestOpenKeyArgs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(keyDirEnv, dir)
	vault := filepath.Join(dir, "zapstore.hotbox")

	path, opts, err := openKeyArgs(filepath.Join(dir, "a.key"), vault)
	if err != nil || path != filepath.Join(dir, "a.key") || len(opts) != 0 {
		t.Fatalf("explicit path=%q opts=%d err=%v", path, len(opts), err)
	}
	path, opts, err = openKeyArgs("", vault)
	if err != nil || path != filepath.Join(dir, "zapstore.key") {
		t.Fatalf("default path=%q err=%v", path, err)
	}
	if vaultcore.KeychainSupported() {
		if len(opts) != 1 {
			t.Fatalf("keychain opts=%d", len(opts))
		}
	} else if len(opts) != 0 {
		t.Fatalf("file opts=%d", len(opts))
	}
}

func TestVaultLabel(t *testing.T) {
	got, err := vaultLabel("/tmp/zapstore.vault")
	if err != nil || got != "zapstore" {
		t.Fatalf("label %s err %v", got, err)
	}
	got, err = vaultLabel("/tmp/releases.hotbox")
	if err != nil || got != "releases" {
		t.Fatalf("label %s err %v", got, err)
	}
	if _, err := vaultLabel("/tmp/a[b].vault"); err == nil {
		t.Fatal("accepted brackets")
	}
}

func TestEnvBlock(t *testing.T) {
	if got := envBlock("zapstore", false, "bunker://abc", "", ""); got != "SIGN_WITH='bunker://abc'\n" {
		t.Fatalf("create %q", got)
	}
	android := "SIGN_WITH='bunker://abc'\nHOTBOX_PIN='pin'\nHOTBOX_SOCKET='/tmp/hotbox.sock'\n"
	if got := envBlock("zapstore", false, "bunker://abc", "pin", "/tmp/hotbox.sock"); got != android {
		t.Fatalf("create android %q", got)
	}
	if got := envBlock("releases", true, "bunker://abc", "pin", "/tmp/hotbox.sock"); got != "[releases]\n"+android {
		t.Fatalf("open %q", got)
	}
}

func TestKeychainEmptyPassphraseBackup(t *testing.T) {
	if !vaultcore.KeychainSupported() {
		t.Skip("keychain is only supported on macOS")
	}
	dir := t.TempDir()
	kc := filepath.Join(dir, "test.keychain-db")
	for _, args := range [][]string{
		{"create-keychain", "-p", "", kc},
		{"set-keychain-settings", kc},
		{"unlock-keychain", "-p", "", kc},
	} {
		out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("security %v: %s", args, out)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("/usr/bin/security", "delete-keychain", kc).Run()
	})
	t.Setenv("VAULTCORE_KEYCHAIN", kc)

	ctx := t.Context()
	secret, err := secretFromInput("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(secret[:]) })
	var connect [32]byte
	var token [16]byte
	connect[0] = 7
	token[0] = 8
	path := filepath.Join(dir, "zapstore.hotbox")
	v, prof, err := profile.Create(ctx, path, "", "zapstore", []byte{}, secret[:], connect, token, 10001, 10002, profile.AndroidKey{}, vaultcore.Keychain())
	if err != nil {
		t.Fatal(err)
	}
	if prof.Npub == "" {
		t.Fatal("missing npub")
	}
	line, err := keyReport(v)
	if err != nil {
		t.Fatal(err)
	}
	stored := v.KeyStorage()
	account := strings.TrimPrefix(stored.Location, vaultcore.KeychainService+"/")
	if account == "" || account == stored.Location {
		t.Fatalf("storage %+v", stored)
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", vaultcore.KeychainService, "-a", account, "-w", kc).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := "Keychain value to back up: " + strings.TrimSpace(string(out))
	if line != want {
		t.Fatalf("line %q want %q", line, want)
	}
	if strings.Contains(line, account) {
		t.Fatalf("backup line contains the vault id %s", account)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	again, opened, err := profile.Open(ctx, path, "", []byte{}, vaultcore.Keychain())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if opened.Npub != prof.Npub || again.KeyStorage().Kind != vaultcore.KeyInKeychain {
		t.Fatalf("reopen npub=%s kind=%s", opened.Npub, again.KeyStorage().Kind)
	}
}

func TestClaimPorts(t *testing.T) {
	used := map[uint16]string{}
	if err := claimPorts(used, "zapstore", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := claimPorts(used, "releases", 2, 3); err == nil {
		t.Fatal("accepted overlapping ports")
	}
	if err := claimPorts(used, "releases", 4, 4); err == nil {
		t.Fatal("accepted a repeated port")
	}
}
