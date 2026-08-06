package api

import (
	"net"
	"os"
)

type peerListener struct {
	net.Listener
	uid int
}

func (listener peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			continue
		}
		uid, err := peerUID(unixConnection)
		if err == nil && uid == listener.uid {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func sameUserListener(listener net.Listener) net.Listener {
	return peerListener{Listener: listener, uid: os.Getuid()}
}
