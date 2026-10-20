package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisplayPath(t *testing.T) {
	t.Chdir(t.TempDir())
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	inside := filepath.Join(working, "app", "release.apk")
	if got, want := displayPath(inside), filepath.Join("app", "release.apk"); got != want {
		t.Fatalf("displayPath(%q) = %q, want %q", inside, got, want)
	}

	const outside = "/other.apk"
	if got := displayPath(outside); got != outside {
		t.Fatalf("displayPath(%q) = %q, want the absolute path", outside, got)
	}
}
