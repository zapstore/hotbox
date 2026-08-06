//go:build linux

package api

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd uintptr) (int, error) {
	credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(credentials.Uid), nil
}
