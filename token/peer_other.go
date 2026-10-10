//go:build !darwin && !linux

package token

import (
	"errors"
	"net"
)

func sameUser(net.Conn) error {
	return errors.New("android signing is supported on darwin and linux")
}
