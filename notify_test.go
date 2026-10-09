package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNotifyReady(t *testing.T) {
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "notify.sock")
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NOTIFY_SOCKET") != "" {
		t.Fatal("NOTIFY_SOCKET still set")
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "READY=1" {
		t.Fatalf("notify %q", buf[:n])
	}
}
