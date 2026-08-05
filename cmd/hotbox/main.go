package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/charmbracelet/huh"
	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"github.com/zapstore/hotbox/internal/api"
	"github.com/zapstore/hotbox/internal/config"
	"github.com/zapstore/hotbox/internal/hardening"
	hotboxnostr "github.com/zapstore/hotbox/internal/nostr"
	"github.com/zapstore/hotbox/internal/toolchain"
	"github.com/zapstore/hotbox/internal/vault"
)

const maxKeystoreSize = 8 << 20

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hotbox:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := hardening.Apply(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "export" {
		return exportKeystore()
	}
	var vaultPath string
	var err error
	switch len(os.Args) {
	case 1:
		vaultName, promptErr := askRequired("Vault filename", "Stored in ~/.hotbox, for example: my-app.hotbox")
		if promptErr != nil {
			return promptErr
		}
		vaultPath, err = config.VaultPath(vaultName)
	case 2:
		vaultPath, err = filepath.Abs(os.Args[1])
	default:
		return fmt.Errorf("usage: hotbox [vault-file]")
	}
	if err != nil {
		return err
	}
	workspace, err := config.Dir()
	if err != nil {
		return err
	}
	if pathWithin(workspace, vaultPath) {
		return fmt.Errorf("vault must be stored outside the signing workspace")
	}
	var data vault.Data
	_, statErr := os.Stat(vaultPath)
	if errors.Is(statErr, os.ErrNotExist) {
		data, err = enroll(ctx, vaultPath)
		if err != nil {
			return err
		}
	} else {
		if statErr != nil {
			return statErr
		}
		var password string
		password, err = askSecret("Hotbox password", "Required")
		if err != nil {
			return err
		}
		data, err = vault.Load(vaultPath, password)
		password = ""
		if err != nil {
			return err
		}
	}
	defer data.Destroy()
	if len(data.Keystores) != 1 {
		return fmt.Errorf("vault must contain exactly one Android keystore; delete it and restart Hotbox")
	}
	var key vault.Keystore
	for _, candidate := range data.Keystores {
		key = candidate
	}
	bunker, err := hotboxnostr.Start(ctx, data.NostrKey)
	if err != nil {
		return err
	}
	socket, err := config.SocketPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Hotbox is ready:", socket)
	server, err := api.New(key, bunker, workspace)
	if err != nil {
		return err
	}
	if err := server.Serve(ctx, socket); err != nil && !api.IsClosed(err) {
		return err
	}
	return nil
}

func exportKeystore() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: hotbox export <vault-file> <output.jks>")
	}
	vaultPath, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(os.Args[3])
	if err != nil {
		return err
	}
	password, err := askSecret("Hotbox password", "Required to export the Android keystore.")
	if err != nil {
		return err
	}
	data, err := vault.Load(vaultPath, password)
	password = ""
	if err != nil {
		return err
	}
	defer data.Destroy()
	if len(data.Keystores) != 1 {
		return fmt.Errorf("vault must contain exactly one Android keystore")
	}
	for _, key := range data.Keystores {
		if err := writeKeystore(outputPath, key.Bytes); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "Android keystore exported:", outputPath)
	return nil
}

func enroll(ctx context.Context, path string) (vault.Data, error) {
	var password, confirm, keystorePath, alias, storePass, storePassConfirm, keyPass, privateKey string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("New Hotbox password").Description("At least 12 characters. Encrypts the immutable vault.").EchoMode(huh.EchoModePassword).Value(&password).Validate(strongPassword),
			huh.NewInput().Title("Confirm Hotbox password").Description("Required.").EchoMode(huh.EchoModePassword).Value(&confirm).Validate(required),
		),
	).WithShowHelp(true)
	if err := form.Run(); err != nil {
		return vault.Data{}, err
	}
	if password == "" || password != confirm {
		return vault.Data{}, fmt.Errorf("passwords did not match")
	}

	keystoreForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Android release keystore path").Description("Optional. Leave blank to create a new Android keystore.").Value(&keystorePath),
			huh.NewInput().Title("Android signing key alias").Description("Required.").Value(&alias).Validate(required),
			huh.NewInput().Title("Nostr private key (nsec)").Description("Optional. Leave blank to generate a new Nostr identity.").EchoMode(huh.EchoModePassword).Value(&privateKey),
		),
	).WithShowHelp(true)
	if err := keystoreForm.Run(); err != nil {
		return vault.Data{}, err
	}
	passwordForm := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Android keystore password").Description("Press Enter to reuse the Hotbox password.").EchoMode(huh.EchoModePassword).Value(&storePass),
		),
	).WithShowHelp(true)
	if err := passwordForm.Run(); err != nil {
		return vault.Data{}, err
	}
	if storePass == "" {
		storePass = password
	} else {
		confirmForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().Title("Confirm Android keystore password").Description("Required.").EchoMode(huh.EchoModePassword).Value(&storePassConfirm).Validate(required),
			),
		).WithShowHelp(true)
		if err := confirmForm.Run(); err != nil {
			return vault.Data{}, err
		}
		if storePass != storePassConfirm {
			return vault.Data{}, fmt.Errorf("android keystore passwords did not match")
		}
	}
	if keyPass == "" {
		keyPass = storePass
	}
	if alias == "" || storePass == "" {
		return vault.Data{}, fmt.Errorf("key alias and keystore password are required")
	}
	var bytes []byte
	if keystorePath == "" {
		var err error
		bytes, err = createKeystore(ctx, alias, storePass, keyPass)
		if err != nil {
			return vault.Data{}, err
		}
	} else {
		absolute, err := filepath.Abs(keystorePath)
		if err != nil {
			return vault.Data{}, err
		}
		bytes, err = readRegularFile(absolute, maxKeystoreSize)
		if err != nil {
			return vault.Data{}, err
		}
	}
	if privateKey == "" {
		privateKey = nostr.GeneratePrivateKey()
	} else {
		var err error
		privateKey, err = decodeNsec(privateKey)
		if err != nil {
			return vault.Data{}, err
		}
	}
	data := vault.New()
	data.Keystores["release"] = vault.Keystore{
		Name: "release", Bytes: bytes, StorePass: storePass, KeyAlias: alias, KeyPass: keyPass,
	}
	data.NostrKey = privateKey
	if err := vault.Save(path, password, data); err != nil {
		data.Destroy()
		return vault.Data{}, err
	}
	fmt.Fprintln(os.Stderr, "Encrypted identity created. To replace it, stop Hotbox and delete:", path)
	return data, nil
}

func createKeystore(ctx context.Context, alias, storePass, keyPass string) ([]byte, error) {
	keytool, err := resolveKeytool()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "hotbox-enroll-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0700); err != nil { // #nosec G302 -- directory requires execute permission.
		return nil, err
	}
	path := filepath.Join(tmp, "release.jks")
	command := toolchain.Command(ctx, keytool,
		"-genkeypair", "-storetype", "JKS", "-keystore", path,
		"-alias", alias, "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000",
		"-dname", "CN=Hotbox", "-noprompt",
	)
	var passwordInput bytes.Buffer
	passwordInput.Grow(2*len(storePass) + 2*len(keyPass) + 4)
	for _, password := range []string{storePass, storePass, keyPass, keyPass} {
		passwordInput.WriteString(password)
		passwordInput.WriteByte('\n')
	}
	defer clear(passwordInput.Bytes())
	command.Stdin = &passwordInput
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("keytool failed: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	bytes, err := readRegularFile(path, maxKeystoreSize)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "Created a new Android keystore inside the encrypted vault.")
	return bytes, nil
}

func decodeNsec(value string) (string, error) {
	if strings.HasPrefix(value, "nsec1") {
		prefix, decoded, err := nip19.Decode(value)
		if err != nil {
			return "", err
		}
		if prefix != "nsec" {
			return "", fmt.Errorf("expected an nsec")
		}
		hexKey, ok := decoded.(string)
		if !ok {
			return "", fmt.Errorf("invalid nsec")
		}
		return hexKey, nil
	}
	if len(value) != 64 {
		return "", fmt.Errorf("expected an nsec or 32-byte hex private key")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("invalid Nostr private key")
	}
	if _, err := nostr.GetPublicKey(value); err != nil {
		return "", fmt.Errorf("invalid Nostr private key")
	}
	return value, nil
}

func askRequired(title, description string) (string, error) {
	var value string
	input := huh.NewInput().Title(title).Description(description).Value(&value).Validate(required)
	if err := input.Run(); err != nil {
		return "", err
	}
	return value, nil
}

func askSecret(title, description string) (string, error) {
	var value string
	input := huh.NewInput().Title(title).Description(description).EchoMode(huh.EchoModePassword).Value(&value).Validate(required)
	if err := input.Run(); err != nil {
		return "", err
	}
	return value, nil
}

func required(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("this value is required")
	}
	return nil
}

func strongPassword(value string) error {
	if err := required(value); err != nil {
		return err
	}
	if len(value) < 12 {
		return errors.New("use at least 12 characters")
	}
	return nil
}

func resolveKeytool() (toolchain.Executable, error) {
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		if path, err := toolchain.Resolve("keytool", filepath.Join(javaHome, "bin", "keytool")); err == nil {
			return path, nil
		}
	}
	return toolchain.Resolve("keytool")
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func pathWithin(root, path string) bool {
	root, rootErr := canonicalPath(root)
	path, pathErr := canonicalPath(path)
	if rootErr != nil || pathErr != nil {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func canonicalPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var missing []string
	for {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", fmt.Errorf("could not resolve path %s", path)
		}
		missing = append(missing, filepath.Base(path))
		path = parent
	}
}

func readRegularFile(path string, maxSize int64) ([]byte, error) {
	// #nosec G304 -- the operator explicitly selects the import path; size and
	// file type are checked on the opened descriptor.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxSize {
		return nil, fmt.Errorf("keystore must be a regular file no larger than %d bytes", maxSize)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maxSize {
		return nil, fmt.Errorf("keystore is too large")
	}
	return contents, nil
}

func writeKeystore(path string, contents []byte) (err error) {
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := output.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err := output.Chmod(0600); err != nil {
		return err
	}
	if _, err := output.Write(contents); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	return nil
}
