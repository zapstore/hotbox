package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsWritableTool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(path); err == nil {
		t.Fatal("Validate accepted a group/world-writable tool")
	}
}

func TestEnvironmentExcludesCredentialsAndProxies(t *testing.T) {
	t.Setenv("HOTBOX_TEST_TOKEN", "secret")
	t.Setenv("HTTPS_PROXY", "https://proxy.example")
	t.Setenv("PATH", "/tmp/attacker-controlled")
	for _, item := range Environment() {
		if strings.HasPrefix(item, "HOTBOX_TEST_TOKEN=") || strings.HasPrefix(item, "HTTPS_PROXY=") {
			t.Fatalf("unsafe environment entry: %q", item)
		}
		if item == "PATH=/tmp/attacker-controlled" {
			t.Fatalf("unsafe PATH entry: %q", item)
		}
	}
}
