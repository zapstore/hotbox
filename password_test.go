package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadPassword(t *testing.T) {
	got, err := readPassword(strings.NewReader("correct horse\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "correct horse" {
		t.Fatalf("password %q", got)
	}
	got, err = readPassword(strings.NewReader("no-newline"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "no-newline" {
		t.Fatalf("eof password %q", got)
	}
	got, err = readPassword(strings.NewReader("\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty line %q err %v", got, err)
	}
	got, err = readPassword(strings.NewReader(""))
	if err != nil || len(got) != 0 {
		t.Fatalf("eof %q err %v", got, err)
	}
	big := strings.Repeat("a", maxPasswordLine+1) + "\n"
	if _, err := readPassword(strings.NewReader(big)); err == nil {
		t.Fatal("accepted a too-large password")
	}
	lines := strings.NewReader("one\r\ntwo\n")
	first, err := readPassword(lines)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readPassword(lines)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, []byte("one")) || !bytes.Equal(second, []byte("two")) {
		t.Fatalf("lines %q %q", first, second)
	}
}

func TestStrongPassword(t *testing.T) {
	if err := strongPassword(""); err != nil {
		t.Fatal(err)
	}
	if err := strongPassword("   "); err != nil {
		t.Fatal(err)
	}
	if err := strongPassword("short"); err == nil {
		t.Fatal("accepted a short password")
	}
	if err := strongPassword("correct horse"); err != nil {
		t.Fatal(err)
	}
}
