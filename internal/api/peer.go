package api

import "net"

func peerUID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		uid, socketErr = peerUIDFromFD(fd)
	}); err != nil {
		return 0, err
	}
	return uid, socketErr
}
