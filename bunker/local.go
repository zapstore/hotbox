package bunker

import (
	"errors"
	"net"
	"net/url"
)

// LocalRelay reports whether raw is a ws or wss URL on a loopback host.
func LocalRelay(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid relay URL")
	}
	switch parsed.Scheme {
	case "ws", "wss":
	default:
		return errors.New("relay scheme must be ws or wss")
	}
	if parsed.User != nil {
		return errors.New("relay URL must not include credentials")
	}
	if parsed.Hostname() == "localhost" {
		return nil
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return errors.New("relay host must be loopback")
	}
	return nil
}
