//go:build linux

package token

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func sameUser(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("signer connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var uid int
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			cerr = err
			return
		}
		uid = int(cred.Uid)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if uid != os.Getuid() {
		return errors.New("signer connection is from another user")
	}
	return nil
}
