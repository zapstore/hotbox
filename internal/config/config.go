package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func Dir() (string, error) {
	base, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return base, nil
}

func VaultPath(filename string) (string, error) {
	if filename == "" || filename == "." || filename == ".." || strings.ContainsRune(filename, filepath.Separator) {
		return "", fmt.Errorf("vault filename must not contain a directory")
	}
	if !strings.HasSuffix(filename, ".hotbox") {
		filename += ".hotbox"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".hotbox")
	return filepath.Join(dir, filename), err
}

const maxUnixSocketPath = 103

// NewSocketPath creates a private, unguessable runtime directory for one
// unlocked daemon session. The caller owns removing the directory.
func NewSocketPath() (string, error) {
	uid := os.Getuid()
	if uid < 0 {
		return "", os.ErrPermission
	}
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return "", fmt.Errorf("resolve runtime directory: %w", err)
	}
	dir, err := os.MkdirTemp(base, "hb-"+strconv.Itoa(uid)+"-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	path := filepath.Join(dir, "s.sock")
	if len(path) > maxUnixSocketPath {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("runtime socket path is too long")
	}
	return path, nil
}

// SocketPath reads the path handed to an API client by the operator.
func SocketPath() (string, error) {
	path := os.Getenv("HOTBOX_SOCKET")
	if path == "" {
		return "", fmt.Errorf("HOTBOX_SOCKET is required")
	}
	if !filepath.IsAbs(path) || len(path) > maxUnixSocketPath {
		return "", fmt.Errorf("HOTBOX_SOCKET must be an absolute Unix socket path")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	uid := os.Getuid()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return "", fmt.Errorf("runtime directory is not owned by the current user")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("runtime directory must be a mode-0700 directory")
	}
	socket, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	socketStat, ok := socket.Sys().(*syscall.Stat_t)
	if !ok || int(socketStat.Uid) != uid {
		return "", fmt.Errorf("runtime socket is not owned by the current user")
	}
	if socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0600 {
		return "", fmt.Errorf("runtime socket must be a mode-0600 Unix socket")
	}
	return path, nil
}
