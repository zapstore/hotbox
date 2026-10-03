package bunker

import (
	"crypto/subtle"
	"testing"
)

func TestSecretPageHoldsThenDestroys(t *testing.T) {
	var src [32]byte
	for i := range src {
		src[i] = byte(i + 1)
	}
	page, err := newSecretPage(src)
	if err != nil {
		t.Fatal(err)
	}
	if subtle.ConstantTimeCompare(page.bytes(), src[:]) != 1 {
		t.Fatal("locked secret does not match")
	}
	if len(page.bytes()) != 32 || cap(page.bytes()) != 32 {
		t.Fatalf("key window len=%d cap=%d", len(page.bytes()), cap(page.bytes()))
	}
	page.destroy()
	page.destroy()
	if page.bytes() != nil {
		t.Fatal("secret remains after destroy")
	}
}
