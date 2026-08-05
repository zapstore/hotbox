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

func SocketPath() (string, error) {
	uid := os.Getuid()
	if uid < 0 {
		return "", os.ErrPermission
	}
	base, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return "", fmt.Errorf("resolve runtime directory: %w", err)
	}
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		base, err = filepath.EvalSymlinks(runtimeDir)
		if err != nil {
			return "", fmt.Errorf("resolve XDG_RUNTIME_DIR: %w", err)
		}
	}
	dir := filepath.Join(base, "hotbox-"+strconv.Itoa(uid))
	// #nosec G703 -- base is canonicalized and the child directory is checked
	// for ownership, type, and exact permissions before use.
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	// #nosec G703 -- see the ownership and mode checks immediately below.
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid {
		return "", fmt.Errorf("runtime directory is not owned by the current user")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("runtime directory must be a mode-0700 directory")
	}
	return filepath.Join(dir, "hotbox.sock"), nil
}
