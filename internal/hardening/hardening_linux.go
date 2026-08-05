//go:build linux

package hardening

import "golang.org/x/sys/unix"

func disableProcessInspection() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
