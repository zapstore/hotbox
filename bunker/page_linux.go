//go:build linux

package bunker

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func protectPage(b []byte) error {
	for _, advice := range []int{unix.MADV_DONTDUMP, unix.MADV_DONTFORK, unix.MADV_WIPEONFORK} {
		if err := unix.Madvise(b, advice); err != nil {
			return fmt.Errorf("protect secret: %w", err)
		}
	}
	return nil
}
