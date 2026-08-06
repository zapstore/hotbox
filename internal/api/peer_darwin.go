//go:build darwin

package api

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd uintptr) (int, error) {
	credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return int(credentials.Uid), nil
}
