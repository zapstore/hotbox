package bunker

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// secretPage is one 32-byte secret on its own locked mapping.
// The following page is unmapped for access so a linear overrun faults
// instead of walking into another vault's key. The page is wiped on destroy.
type secretPage struct {
	mem  []byte
	key  []byte
	page int
}

func newSecretPage(src [32]byte) (*secretPage, error) {
	defer wipe32(&src)
	page := unix.Getpagesize()
	if page < 32 {
		return nil, errors.New("page size too small for a secret")
	}
	mem, err := unix.Mmap(-1, 0, page*2, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("allocate secret: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = unix.Munmap(mem)
		}
	}()
	if err := unix.Mprotect(mem[page:], unix.PROT_NONE); err != nil {
		return nil, fmt.Errorf("guard secret: %w", err)
	}
	if err := unix.Mlock(mem[:page]); err != nil {
		return nil, fmt.Errorf("lock secret: %w", err)
	}
	if err := protectPage(mem[:page]); err != nil {
		_ = unix.Munlock(mem[:page])
		return nil, err
	}
	key := mem[page-32 : page : page]
	copy(key, src[:])
	ok = true
	return &secretPage{mem: mem, key: key, page: page}, nil
}

func (s *secretPage) bytes() []byte {
	if s == nil {
		return nil
	}
	return s.key
}

func (s *secretPage) destroy() {
	if s == nil || s.mem == nil {
		return
	}
	page := s.mem[:s.page]
	for i := range page {
		page[i] = 0
	}
	runtime.KeepAlive(page)
	_ = unix.Munlock(page)
	_ = unix.Munmap(s.mem)
	s.mem = nil
	s.key = nil
}

func wipe32(b *[32]byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
