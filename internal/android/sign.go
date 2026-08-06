package android

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zapstore/hotbox/internal/toolchain"
	"github.com/zapstore/hotbox/internal/vault"
)

type Result struct {
	Output            string `json:"output"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
}

// SignAPK signs a finished, unsigned APK. It never runs Gradle or interprets
// build configuration supplied by the caller.
func SignAPK(ctx context.Context, workspace, input, output string, key vault.Keystore, alias, password string, overwrite bool) (Result, error) {
	if !hasAlias(key.Aliases, alias) {
		return Result{}, fmt.Errorf("unknown signing alias")
	}
	workspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return Result{}, fmt.Errorf("resolve workspace: %w", err)
	}
	workspace, err = filepath.Abs(workspace)
	if err != nil {
		return Result{}, fmt.Errorf("resolve workspace: %w", err)
	}
	input, err = canonicalAPK(input)
	if err != nil {
		return Result{}, err
	}
	if !within(workspace, input) {
		return Result{}, fmt.Errorf("input must be inside the configured workspace (%s)", workspace)
	}
	if output == "" {
		output = strings.TrimSuffix(input, ".apk") + "-signed.apk"
	}
	output, err = outputPath(input, output)
	if err != nil {
		return Result{}, err
	}
	if output == input {
		return Result{}, fmt.Errorf("output must differ from input")
	}
	if err := checkOutput(output, overwrite); err != nil {
		return Result{}, err
	}
	apksigner, zipalign, err := tools()
	if err != nil {
		return Result{}, err
	}

	tmp, err := os.MkdirTemp("", "hotbox-*")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0700); err != nil { // #nosec G302 -- directory requires execute permission.
		return Result{}, err
	}
	keystore := filepath.Join(tmp, "release.jks")
	if err := os.WriteFile(keystore, key.Bytes, 0600); err != nil {
		return Result{}, err
	}
	signingInput := filepath.Join(tmp, "input.apk")
	if err := copyRegularFile(input, signingInput, 0600); err != nil {
		return Result{}, fmt.Errorf("copy input APK: %w", err)
	}
	if err := toolchain.Command(ctx, apksigner, "verify", signingInput).Run(); err == nil {
		return Result{}, fmt.Errorf("input APK is already signed")
	}
	aligned := filepath.Join(tmp, "aligned.apk")
	if zipalign.Valid() {
		cmd := toolchain.Command(ctx, zipalign, "-f", "-p", "4", signingInput, aligned)
		if err := cmd.Run(); err != nil {
			return Result{}, fmt.Errorf("zipalign failed: %w", err)
		}
	} else {
		aligned = signingInput
	}
	signed := filepath.Join(tmp, "signed.apk")
	cmd := toolchain.Command(ctx, apksigner, "sign",
		"--ks", keystore,
		"--ks-key-alias", alias,
		"--ks-pass", "stdin",
		"--key-pass", "stdin",
		"--out", signed,
		aligned,
	)
	var passwordInput bytes.Buffer
	passwordInput.Grow(2*len(password) + 2)
	passwordInput.WriteString(password)
	passwordInput.WriteByte('\n')
	passwordInput.WriteString(password)
	passwordInput.WriteByte('\n')
	defer clear(passwordInput.Bytes())
	cmd.Stdin = &passwordInput
	if err := cmd.Run(); err != nil {
		return Result{}, fmt.Errorf("apksigner failed: %w", err)
	}
	verify := toolchain.Command(ctx, apksigner, "verify", "--verbose", "--print-certs", signed)
	commandOutput, err := verify.CombinedOutput()
	defer clear(commandOutput)
	if err != nil {
		return Result{}, fmt.Errorf("signed APK verification failed: %w", err)
	}
	if err := publishFile(signed, output, overwrite); err != nil {
		return Result{}, err
	}
	return Result{Output: output, CertificateSHA256: certificateDigest(string(commandOutput))}, nil
}

func hasAlias(aliases []string, target string) bool {
	for _, alias := range aliases {
		if alias == target {
			return true
		}
	}
	return false
}

func canonicalAPK(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if strings.ToLower(filepath.Ext(absolute)) != ".apk" {
		return "", fmt.Errorf("input must be an APK")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("input must be a regular APK file")
	}
	return resolved, nil
}

func outputPath(input, output string) (string, error) {
	absolute, err := filepath.Abs(output)
	if err != nil {
		return "", err
	}
	if strings.ToLower(filepath.Ext(absolute)) != ".apk" {
		return "", fmt.Errorf("output must be an APK")
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	absolute = filepath.Join(dir, filepath.Base(absolute))
	if dir != filepath.Dir(input) {
		return "", fmt.Errorf("output must be alongside the input APK")
	}
	return absolute, nil
}

func checkOutput(path string, overwrite bool) error {
	if _, err := os.Lstat(path); err == nil {
		if !overwrite {
			return fmt.Errorf("refusing to overwrite existing output")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func within(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func tools() (apksigner, zipalign toolchain.Executable, err error) {
	if err := toolchain.ValidateJava(); err != nil {
		return apksigner, zipalign, err
	}
	sdk := os.Getenv("ANDROID_HOME")
	if sdk == "" {
		sdk = os.Getenv("ANDROID_SDK_ROOT")
	}
	if sdk != "" {
		entries, readErr := os.ReadDir(filepath.Join(sdk, "build-tools"))
		if readErr != nil {
			return apksigner, zipalign, readErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
		for _, entry := range entries {
			candidate := filepath.Join(sdk, "build-tools", entry.Name(), "apksigner")
			apksigner, err = toolchain.Validate(candidate)
			if err != nil {
				continue
			}
			zipalign, _ = toolchain.Validate(filepath.Join(sdk, "build-tools", entry.Name(), "zipalign"))
			return apksigner, zipalign, nil
		}
	}
	apksigner, err = toolchain.Resolve("apksigner")
	if err != nil {
		return apksigner, zipalign, fmt.Errorf("apksigner not found; set ANDROID_HOME or add it to PATH")
	}
	if candidate, lookErr := toolchain.Resolve("zipalign"); lookErr == nil {
		zipalign = candidate
	}
	return apksigner, zipalign, nil
}

func certificateDigest(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if _, digest, ok := strings.Cut(line, "certificate SHA-256 digest:"); ok {
			return strings.TrimSpace(digest)
		}
	}
	return ""
}

func copyRegularFile(source, destination string, mode os.FileMode) error {
	// #nosec G304 -- callers pass a canonical workspace input or a path inside
	// a freshly created private scratch directory.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	// #nosec G304 -- destination is inside the private scratch directory.
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func publishFile(source, destination string, overwrite bool) error {
	staged, err := os.CreateTemp(filepath.Dir(destination), ".hotbox-signed-*.apk")
	if err != nil {
		return err
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	defer staged.Close()
	// #nosec G304 -- source is a verified file in private scratch storage.
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if _, err := io.Copy(staged, input); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if err := staged.Chmod(0644); err != nil {
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if overwrite {
		if err := os.Rename(stagedPath, destination); err != nil {
			return err
		}
		return nil
	}
	if err := os.Link(stagedPath, destination); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing output")
		}
		return err
	}
	return nil
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
