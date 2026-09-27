package main

import (
	"net"
	"os"
	"strings"
)

// notifyReady tells systemd the service has unlocked and is listening.
// It does nothing when the process was not started as Type=notify.
func notifyReady() error {
	return sdNotify("READY=1")
}

func sdNotify(state string) error {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return nil
	}
	conn, err := net.DialUnix("unixgram", nil, notifyAddr(name))
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return err
	}
	return os.Unsetenv("NOTIFY_SOCKET")
}

func notifyAddr(name string) *net.UnixAddr {
	if strings.HasPrefix(name, "@") {
		return &net.UnixAddr{Name: "\x00" + name[1:], Net: "unixgram"}
	}
	return &net.UnixAddr{Name: name, Net: "unixgram"}
}
