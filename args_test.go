package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
