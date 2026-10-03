package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseArgs(t *testing.T) {
	paths, help, err := parseArgs([]string{"/tmp/a.hotbox", "/tmp/b.hotbox"})
	if err != nil {
		t.Fatal(err)
	}
	if help || len(paths) != 2 || paths[0] != "/tmp/a.hotbox" {
		t.Fatalf("paths=%v help=%v", paths, help)
	}
	if _, help, err := parseArgs([]string{"--help"}); err != nil || !help {
		t.Fatalf("help err=%v help=%v", err, help)
	}
	if _, _, err := parseArgs([]string{"--prompt"}); err == nil {
		t.Fatal("accepted --prompt")
	}
	if _, _, err := parseArgs([]string{"--nope"}); err == nil {
		t.Fatal("accepted unknown flag")
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
	got, err = resolvePath("keys/zapstore.hotbox")
	if err != nil || got != filepath.Join(cwd, "keys", "zapstore.hotbox") {
		t.Fatalf("path %s err %v", got, err)
	}
	got, err = resolvePath("/tmp/zapstore.hotbox")
	if err != nil || got != "/tmp/zapstore.hotbox" {
		t.Fatalf("path %s err %v", got, err)
	}
	home, err := resolvePath("~/vaults/zapstore.hotbox")
	if err != nil || home == "~/vaults/zapstore.hotbox" || home[0] != '/' {
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
	if err != nil || got != filepath.Join(home, ".local", "share", "hotbox") {
		t.Fatalf("default key dir %s err %v", got, err)
	}
	t.Setenv(keyDirEnv, "~/hotbox-keys")
	got, err = keyDir()
	if err != nil || got[0] != '/' || filepath.Base(got) != "hotbox-keys" {
		t.Fatalf("env key dir %s err %v", got, err)
	}
}

func TestVaultLabel(t *testing.T) {
	got, err := vaultLabel("/tmp/zapstore.hotbox")
	if err != nil || got != "zapstore" {
		t.Fatalf("label %s err %v", got, err)
	}
	if _, err := vaultLabel("/tmp/a[b].hotbox"); err == nil {
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
