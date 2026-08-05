//go:build darwin || linux

// Package hardening applies process-level controls that reduce secret exposure.
package hardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Apply disables core dumps and platform-specific process inspection before
// the vault is unlocked.
func Apply() error {
	limit := &unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, limit); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := disableProcessInspection(); err != nil {
		return fmt.Errorf("disable process inspection: %w", err)
	}
	return nil
}
