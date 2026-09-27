package main

import (
	"strings"
	"testing"
)

func TestReadPassword(t *testing.T) {
	got, err := readPassword(strings.NewReader("correct horse\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "correct horse" {
		t.Fatalf("password %q", got)
	}
	got, err = readPassword(strings.NewReader("no-newline"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "no-newline" {
		t.Fatalf("eof password %q", got)
	}
	if _, err := readPassword(strings.NewReader("\n")); err == nil {
		t.Fatal("accepted empty password")
	}
	if _, err := readPassword(strings.NewReader("")); err == nil {
		t.Fatal("accepted eof")
	}
	big := strings.Repeat("a", maxPasswordLine+1) + "\n"
	if _, err := readPassword(strings.NewReader(big)); err == nil {
		t.Fatal("accepted a too-large password")
	}
}
