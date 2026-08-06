package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

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
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help") {
		printUsage(os.Stdout)
		return nil
	}
	if err := hardening.Apply(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "export" {
		return exportKeystore()
	}
	if len(os.Args) > 1 && os.Args[1] == "add-alias" {
		return addAlias()
	}
	if len(os.Args) > 1 && os.Args[1] == "bunker" {
		return runWithBunker()
	}
	if len(os.Args) > 1 && os.Args[1] == "status" {
		return statusCommand()
	}
	if len(os.Args) > 1 && os.Args[1] == "sign" {
		return signCommand()
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
		vaultPath, err = resolveVaultArgument(os.Args[1])
	default:
		return fmt.Errorf("usage: hotbox [vault-file]; run hotbox --help for details")
	}
	if err != nil {
		return err
	}
	workspace, err := config.Dir()
	if err != nil {
		return err
	}
	var data vault.Data
	var password string
	_, statErr := os.Stat(vaultPath)
	if errors.Is(statErr, os.ErrNotExist) {
		data, password, err = enroll(ctx, vaultPath)
		if err != nil {
			return err
		}
	} else {
		if statErr != nil {
			return statErr
		}
		password, err = askSecret("Hotbox password", "Required")
		if err != nil {
			return err
		}
		data, err = vault.Load(vaultPath, password)
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
	aliases, err := certificateAliases(ctx, key, password)
	if err != nil {
		return err
	}
	bunker, err := hotboxnostr.Start(ctx, data.NostrKey)
	if err != nil {
		return err
	}
	socket, err := config.NewSocketPath()
	if err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Dir(socket))
	zsp, _ := toolchain.Resolve("zsp")
	keytool, _ := resolveKeytool()
	server, err := api.New(key, password, bunker, workspace, aliases, zsp, keytool, relayURLs())
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Hotbox unlocked:", socket, "workspace="+server.Workspace())
	if err := server.Serve(ctx, socket); err != nil && !api.IsClosed(err) {
		return err
	}
	return nil
}

func relayURLs() []string {
	value := os.Getenv("RELAY_URLS")
	if value == "" {
		return []string{"wss://relay.zapstore.dev"}
	}
	var relays []string
	for _, relay := range strings.Split(value, ",") {
		if relay = strings.TrimSpace(relay); relay != "" {
			relays = append(relays, relay)
		}
	}
	return relays
}

func resolveVaultArgument(argument string) (string, error) {
	if !filepath.IsAbs(argument) && !strings.ContainsRune(argument, filepath.Separator) {
		namedVault, err := config.VaultPath(argument)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(namedVault); err == nil {
			return namedVault, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return filepath.Abs(argument)
}

func vaultCommonName(path string) string {
	name := strings.TrimSuffix(filepath.Base(path), ".hotbox")
	if name == "" {
		return "Hotbox"
	}
	return name
}

func printUsage(output io.Writer) {
	fmt.Fprint(output, `Usage:
  hotbox [vault-file]
  hotbox export <vault-file> <output.jks>
  hotbox add-alias <vault-file> <alias>
  hotbox status --json
  hotbox sign --alias NAME [--overwrite] <input.apk> <output.apk>
  hotbox bunker --env NAME [--ttl 15m] -- command [args...]

Start Hotbox from the project workspace whose APKs it may sign.
Set HOTBOX_SOCKET to the random path printed by the unlocked daemon before
using status, sign, or bunker client commands.
`)
}

func statusCommand() error {
	if len(os.Args) != 3 || os.Args[2] != "--json" {
		return fmt.Errorf("usage: hotbox status --json")
	}
	return proxyDaemonRequest(http.MethodGet, "/v1/status", nil)
}

func signCommand() error {
	args := os.Args[2:]
	var alias string
	overwrite := false
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch args[0] {
		case "--alias":
			if len(args) < 2 {
				return fmt.Errorf("usage: hotbox sign --alias NAME [--overwrite] <input.apk> <output.apk>")
			}
			alias = args[1]
			args = args[2:]
		case "--overwrite":
			overwrite = true
			args = args[1:]
		default:
			return fmt.Errorf("usage: hotbox sign --alias NAME [--overwrite] <input.apk> <output.apk>")
		}
	}
	if alias == "" || len(args) != 2 {
		return fmt.Errorf("usage: hotbox sign --alias NAME [--overwrite] <input.apk> <output.apk>")
	}
	input, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	output, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Input     string `json:"input"`
		Output    string `json:"output"`
		Alias     string `json:"alias"`
		Overwrite bool   `json:"overwrite,omitempty"`
	}{Input: input, Output: output, Alias: alias, Overwrite: overwrite})
	if err != nil {
		return err
	}
	return proxyDaemonRequest(http.MethodPost, "/v1/sign-apk", bytes.NewReader(body))
}

func proxyDaemonRequest(method, path string, body io.Reader) error {
	response, err := daemonRequest(method, path, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	output := io.Writer(os.Stdout)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		output = os.Stderr
	}
	if _, err := io.Copy(output, response.Body); err != nil {
		return err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Hotbox returned %s", response.Status)
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
		metadataPath := outputPath + ".json"
		if _, err := os.Lstat(metadataPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing metadata: %s", metadataPath)
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := writeKeystore(outputPath, key.Bytes); err != nil {
			return err
		}
		publicKey, err := nostr.GetPublicKey(data.NostrKey)
		if err != nil {
			_ = os.Remove(outputPath)
			return fmt.Errorf("read Nostr public key: %w", err)
		}
		npub, err := nip19.EncodePublicKey(publicKey)
		if err != nil {
			_ = os.Remove(outputPath)
			return fmt.Errorf("encode Nostr public key: %w", err)
		}
		metadata, err := json.MarshalIndent(exportMetadata{Aliases: key.Aliases, Npub: npub}, "", "  ")
		if err != nil {
			_ = os.Remove(outputPath)
			return err
		}
		if err := writeMetadata(metadataPath, metadata); err != nil {
			_ = os.Remove(outputPath)
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "Android keystore exported:", outputPath)
	return nil
}

type exportMetadata struct {
	Aliases []string `json:"aliases"`
	Npub    string   `json:"npub"`
}

func runWithBunker() error {
	args := os.Args[2:]
	if len(args) < 4 || args[0] != "--env" || !validEnvironmentName(args[1]) {
		return fmt.Errorf("usage: hotbox bunker --env NAME [--ttl 15m] -- command [args...]")
	}
	environmentName := args[1]
	args = args[2:]
	ttl := 15 * time.Minute
	if len(args) >= 2 && args[0] == "--ttl" {
		var err error
		ttl, err = time.ParseDuration(args[1])
		if err != nil || ttl <= 0 || ttl > time.Hour {
			return fmt.Errorf("ttl must be greater than zero and no more than one hour")
		}
		args = args[2:]
	}
	if len(args) < 2 || args[0] != "--" {
		return fmt.Errorf("usage: hotbox bunker --env NAME [--ttl 15m] -- command [args...]")
	}
	session, err := bunkerURL(ttl)
	if err != nil {
		return err
	}
	defer revokeBunkerSession(session.ID)
	command := exec.Command(args[1], args[2:]...) // #nosec G204 -- the operator explicitly chooses the child command.
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = replaceEnvironment(os.Environ(), environmentName, session.URL)
	if err := command.Run(); err != nil {
		return fmt.Errorf("run bunker client: %w", err)
	}
	return nil
}

type bunkerSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func bunkerURL(ttl time.Duration) (bunkerSession, error) {
	body, err := json.Marshal(struct {
		TTL string `json:"ttl"`
	}{TTL: ttl.String()})
	if err != nil {
		return bunkerSession{}, err
	}
	response, err := daemonRequest(http.MethodPost, "/v1/nostr/sessions", bytes.NewReader(body))
	if err != nil {
		return bunkerSession{}, fmt.Errorf("request bunker URL: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return bunkerSession{}, fmt.Errorf("request bunker URL: Hotbox returned %s", response.Status)
	}
	var decoded bunkerSession
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil || decoded.ID == "" || decoded.URL == "" {
		return bunkerSession{}, fmt.Errorf("request bunker URL: invalid Hotbox response")
	}
	return decoded, nil
}

func revokeBunkerSession(id string) {
	response, err := daemonRequest(http.MethodDelete, "/v1/nostr/sessions/"+url.PathEscape(id), nil)
	if err == nil {
		_ = response.Body.Close()
	}
}

func daemonRequest(method, path string, body io.Reader) (*http.Response, error) {
	socket, err := config.SocketPath()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	request, err := http.NewRequest(method, "http://localhost"+path, body)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return response, nil
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for index, character := range name {
		if character == '_' || character >= 'A' && character <= 'Z' || index > 0 && character >= '0' && character <= '9' {
			continue
		}
		return false
	}
	return true
}

func replaceEnvironment(environment []string, name, value string) []string {
	prefix := name + "="
	filtered := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, prefix+value)
}

func addAlias() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: hotbox add-alias <vault-file> <alias>")
	}
	vaultPath, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	alias := os.Args[3]
	if err := required(alias); err != nil {
		return fmt.Errorf("alias: %w", err)
	}
	password, err := askSecret("Hotbox password", "Required to add an Android signing alias.")
	if err != nil {
		return err
	}
	data, err := vault.Load(vaultPath, password)
	if err != nil {
		return err
	}
	defer data.Destroy()
	if len(data.Keystores) != 1 {
		return fmt.Errorf("vault must contain exactly one Android keystore")
	}
	for name, key := range data.Keystores {
		if slices.Contains(key.Aliases, alias) {
			return fmt.Errorf("signing alias already exists")
		}
		contents, err := addKeyAlias(context.Background(), key.Bytes, alias, password, vaultCommonName(vaultPath))
		if err != nil {
			return err
		}
		clear(key.Bytes)
		key.Bytes = contents
		key.Aliases = append(key.Aliases, alias)
		data.Keystores[name] = key
	}
	if err := vault.Replace(vaultPath, password, data); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Android signing alias added:", alias)
	return nil
}

func enroll(ctx context.Context, path string) (vault.Data, string, error) {
	var password, confirm, keystorePath, alias, privateKey string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("New Hotbox password").Description("At least 12 characters. Encrypts the vault and Android keystore.").EchoMode(huh.EchoModePassword).Value(&password).Validate(strongPassword),
			huh.NewInput().Title("Confirm Hotbox password").Description("Required.").EchoMode(huh.EchoModePassword).Value(&confirm).Validate(required),
			huh.NewInput().Title("Android release keystore path").Description("Optional. Leave blank to create a new Android keystore.").Value(&keystorePath),
			huh.NewInput().Title("Initial Android signing key alias").Description("Required. Add another app later with hotbox add-alias.").Value(&alias).Validate(required),
			huh.NewInput().Title("Nostr private key (nsec)").Description("Optional. Leave blank to generate a shared Nostr identity.").EchoMode(huh.EchoModePassword).Value(&privateKey),
		),
	).WithShowHelp(true)
	if err := form.Run(); err != nil {
		return vault.Data{}, "", err
	}
	if password == "" || password != confirm {
		return vault.Data{}, "", fmt.Errorf("passwords did not match")
	}
	var bytes []byte
	if keystorePath == "" {
		var err error
		bytes, err = createKeystore(ctx, alias, password, vaultCommonName(path))
		if err != nil {
			return vault.Data{}, "", err
		}
	} else {
		absolute, err := filepath.Abs(keystorePath)
		if err != nil {
			return vault.Data{}, "", err
		}
		bytes, err = readRegularFile(absolute, maxKeystoreSize)
		if err != nil {
			return vault.Data{}, "", err
		}
	}
	if privateKey == "" {
		privateKey = nostr.GeneratePrivateKey()
	} else {
		var err error
		privateKey, err = decodeNsec(privateKey)
		if err != nil {
			return vault.Data{}, "", err
		}
	}
	data := vault.New()
	data.Keystores["release"] = vault.Keystore{
		Name: "release", Bytes: bytes, Aliases: []string{alias},
	}
	data.NostrKey = privateKey
	if err := vault.Save(path, password, data); err != nil {
		data.Destroy()
		return vault.Data{}, "", err
	}
	fmt.Fprintln(os.Stderr, "Encrypted identity created:", path)
	return data, password, nil
}

func createKeystore(ctx context.Context, alias, password, commonName string) ([]byte, error) {
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
		"-dname", "CN="+commonName, "-noprompt",
	)
	var passwordInput bytes.Buffer
	passwordInput.Grow(4*len(password) + 4)
	for range 4 {
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

func addKeyAlias(ctx context.Context, contents []byte, alias, password, commonName string) ([]byte, error) {
	keytool, err := resolveKeytool()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "hotbox-alias-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(tmp, "release.jks")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		return nil, err
	}
	command := toolchain.Command(ctx, keytool,
		"-genkeypair", "-storetype", "JKS", "-keystore", path,
		"-alias", alias, "-keyalg", "RSA", "-keysize", "4096", "-validity", "10000",
		"-dname", "CN="+commonName, "-noprompt",
	)
	var passwordInput bytes.Buffer
	passwordInput.Grow(4*len(password) + 4)
	for range 4 {
		passwordInput.WriteString(password)
		passwordInput.WriteByte('\n')
	}
	defer clear(passwordInput.Bytes())
	command.Stdin = &passwordInput
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("keytool add alias failed: %w", err)
	}
	return readRegularFile(path, maxKeystoreSize)
}

func certificateAliases(ctx context.Context, key vault.Keystore, password string) ([]api.Alias, error) {
	keytool, err := resolveKeytool()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "hotbox-certificates-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(tmp, "release.jks")
	if err := os.WriteFile(path, key.Bytes, 0600); err != nil {
		return nil, err
	}
	aliases := make([]api.Alias, 0, len(key.Aliases))
	for _, name := range key.Aliases {
		command := toolchain.Command(ctx, keytool,
			"-list", "-v", "-storetype", "JKS", "-keystore", path, "-alias", name,
		)
		command.Stdin = strings.NewReader(password + "\n")
		output, err := command.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("inspect certificate for alias %q: %w", name, err)
		}
		certificate := api.Alias{Name: name}
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if value, ok := strings.CutPrefix(line, "Owner: "); ok {
				certificate.CertificateDN = value
			}
			if value, ok := strings.CutPrefix(line, "SHA256: "); ok {
				certificate.CertificateSHA256 = strings.ReplaceAll(value, ":", "")
			}
		}
		if certificate.CertificateDN == "" || certificate.CertificateSHA256 == "" {
			return nil, fmt.Errorf("inspect certificate for alias %q: missing certificate metadata", name)
		}
		aliases = append(aliases, certificate)
	}
	return aliases, nil
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

func writeMetadata(path string, contents []byte) (err error) {
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
	if _, err := output.Write(contents); err != nil {
		return err
	}
	if _, err := output.Write([]byte("\n")); err != nil {
		return err
	}
	return output.Sync()
}
