//go:build darwin

package hardening

import "golang.org/x/sys/unix"

func disableProcessInspection() error {
	return unix.PtraceDenyAttach()
}
