package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNewSocketPathUsesRandomPrivateRuntimeDirectory(t *testing.T) {
	first, err := NewSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(first)) })
	second, err := NewSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(second)) })
	if first == second {
		t.Fatal("daemon sessions reused a socket path")
	}
	if len(first) > maxUnixSocketPath {
		t.Fatalf("socket path is too long: %d", len(first))
	}
	info, err := os.Stat(filepath.Dir(first))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("runtime directory mode = %o", info.Mode().Perm())
	}
	if filepath.Base(first) != "s.sock" {
		t.Fatalf("socket path = %q", first)
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

func TestSocketPathRequiresOperatorHandoff(t *testing.T) {
	t.Setenv("HOTBOX_SOCKET", "")
	if _, err := SocketPath(); err == nil {
		t.Fatal("SocketPath accepted an empty handoff")
	}
}

func TestSocketPathValidatesPrivateRuntimeDirectory(t *testing.T) {
	generated, err := NewSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(generated)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOTBOX_SOCKET", path)
	if got, err := SocketPath(); err != nil || got != path {
		t.Fatalf("SocketPath() = %q, %v", got, err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := SocketPath(); err == nil {
		t.Fatal("SocketPath accepted an insecure runtime directory")
	}
}
