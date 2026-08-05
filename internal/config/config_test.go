package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSocketPathUsesPrivateRuntimeDirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)
	socket, err := SocketPath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("runtime directory mode = %o", info.Mode().Perm())
	}
	if filepath.Base(socket) != "hotbox.sock" {
		t.Fatalf("socket path = %q", socket)
	}
}

func TestVaultPathUsesHotboxDirectoryInHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := VaultPath("release.hotbox")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".hotbox", "release.hotbox"); path != want {
		t.Fatalf("VaultPath() = %q", path)
	}
	path, err = VaultPath("release")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "release.hotbox" {
		t.Fatalf("VaultPath() did not add extension: %q", path)
	}
}

func TestSocketPathRejectsInsecureRuntimeDirectory(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", base)
	dir := filepath.Join(base, "hotbox-"+strconv.Itoa(os.Getuid()))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := SocketPath(); err == nil {
		t.Fatal("SocketPath accepted an insecure runtime directory")
	}
}
