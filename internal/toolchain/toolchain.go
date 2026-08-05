// Package toolchain validates and starts the external Android signing tools.
package toolchain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Executable is a canonical path that passed Validate.
type Executable struct {
	path string
}

// Valid reports whether the executable has been resolved.
func (executable Executable) Valid() bool {
	return executable.path != ""
}

// Resolve returns a canonical, non-group-writable executable. Preferred paths
// are checked before PATH.
func Resolve(name string, preferred ...string) (Executable, error) {
	for _, path := range preferred {
		if path == "" {
			continue
		}
		if resolved, err := Validate(path); err == nil {
			return resolved, nil
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return Executable{}, fmt.Errorf("%s not found in configured toolchain or PATH", name)
	}
	return Validate(path)
}

// Validate canonicalizes an executable and rejects unsafe file modes.
func Validate(path string) (Executable, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Executable{}, err
	}
	absolute, err := filepath.Abs(resolved)
	if err != nil {
		return Executable{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return Executable{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return Executable{}, fmt.Errorf("tool is not an executable regular file: %s", absolute)
	}
	if info.Mode().Perm()&0022 != 0 {
		return Executable{}, fmt.Errorf("refusing group/world-writable tool: %s", absolute)
	}
	return Executable{path: absolute}, nil
}

// Command creates a cancellable child with a minimal, credential-free
// environment.
func Command(ctx context.Context, executable Executable, args ...string) *exec.Cmd {
	if !executable.Valid() {
		panic("toolchain: unresolved executable")
	}
	// #nosec G204 -- Executable values can only be constructed by Validate.
	cmd := exec.CommandContext(ctx, executable.path, args...)
	cmd.Env = Environment()
	return cmd
}

// Environment returns only variables needed by the Android SDK and JDK.
func Environment() []string {
	allowed := map[string]bool{
		"ANDROID_HOME": true, "ANDROID_SDK_ROOT": true, "HOME": true,
		"JAVA_HOME": true, "LANG": true, "LOGNAME": true,
		"TMPDIR": true, "USER": true,
	}
	var env []string
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if allowed[name] || strings.HasPrefix(name, "LC_") {
			env = append(env, item)
		}
	}
	path := "/usr/bin:/bin:/usr/sbin:/sbin"
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		path = filepath.Join(javaHome, "bin") + string(os.PathListSeparator) + path
	}
	env = append(env, "PATH="+path)
	return env
}

// ValidateJava rejects an unsafe Java launcher before a signing tool can
// receive keystore material.
func ValidateJava() error {
	path := "/usr/bin/java"
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		path = filepath.Join(javaHome, "bin", "java")
	}
	if _, err := Validate(path); err != nil {
		return fmt.Errorf("validate Java runtime: %w", err)
	}
	return nil
}
