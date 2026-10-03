//go:build !linux

package bunker

func protectPage([]byte) error { return nil }
