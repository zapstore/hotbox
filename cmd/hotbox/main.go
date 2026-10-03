package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/charmbracelet/huh"
	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/sys/unix"

	"github.com/zapstore/hotbox/internal/bunker"
	"github.com/zapstore/hotbox/internal/vault"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hotbox:", err)
		os.Exit(1)
	}
}

func run() error {
	paths, help, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if help {
		fmt.Fprint(os.Stdout, `Usage:
  hotbox
      Create a vault. Asks for a path, an nsec, and a password, prints the npub, then runs the bunker.
  hotbox <vault.hotbox> [more.hotbox ...]
      Unlock each vault and run a bunker for each.
      A relative path is taken from the working directory. A leading ~/ is expanded.

Creating a vault also writes a key file in the key directory: $HOTBOX_KEYS if
set, otherwise `+defaultKeyDirHelp+`. Opening a vault needs
its password and its key file. Neither the nsec nor the key file can be
recovered from the vault; if one is lost, create a new vault from your nsec.

On a terminal, asks for each vault password. When stdin is not a terminal
(a pipe, or a service that passes passwords on stdin), reads one line per
vault, in the same order as the paths.
Prints [name] SIGN_WITH='bunker://…' for each vault.
Under systemd Type=notify, signals ready after every vault is listening.

The bunker listens on 127.0.0.1 only, with ws and wss, and does not dial the network.
`)
		return nil
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(paths) == 0 {
		return createAndRun(ctx)
	}
	return openAndRun(ctx, paths)
}

func parseArgs(args []string) (paths []string, help bool, err error) {
	for _, arg := range args {
		switch arg {
		case "--help", "-h":
			help = true
		case "help":
			if len(args) == 1 {
				help = true
				continue
			}
			paths = append(paths, arg)
		default:
			if strings.HasPrefix(arg, "-") {
				return nil, false, fmt.Errorf("unknown flag %s", arg)
			}
			paths = append(paths, arg)
		}
	}
	return paths, help, nil
}

func createAndRun(ctx context.Context) error {
	raw, err := ask("Vault path", "Vault file. A relative path is taken from the working directory.", false, required)
	if err != nil {
		return err
	}
	path, err := resolvePath(raw)
	if err != nil {
		return err
	}
	label, err := vaultLabel(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault %s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	nsec, err := ask("Nostr private key", "nsec1… or 64-character hex. It is sealed inside the vault.", true, validNsec)
	if err != nil {
		return err
	}
	password, err := askNewPassword()
	if err != nil {
		return err
	}
	secret, err := secretFromInput(nsec)
	if err != nil {
		return err
	}
	defer clear(secret[:])
	wsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	wssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = wsLn.Close()
		return err
	}
	state := vault.State{Secret: secret}
	defer state.Wipe()
	if _, err := rand.Read(state.Connect[:]); err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	if _, err := rand.Read(state.Token[:]); err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	state.WSPort, err = tcpPort(wsLn)
	if err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	state.WSSPort, err = tcpPort(wssLn)
	if err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	keys, err := keyDir()
	if err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	pw := []byte(password)
	keyPath, err := vault.Create(path, keys, pw, state)
	clear(pw)
	if err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	npub, err := npubFromSecret(state.Secret)
	if err != nil {
		_ = wsLn.Close()
		_ = wssLn.Close()
		return err
	}
	fmt.Fprintf(os.Stderr, "created %s\nkey file %s (needed with the password to open the vault; not recoverable)\n[%s] %s\n", path, keyPath, label, npub)
	started, err := bunker.Start(ctx, state.Secret, state.Connect, state.Token, wsLn, wssLn, nil)
	state.Wipe()
	clear(secret[:])
	if err != nil {
		return err
	}
	return serve([]signer{{label: label, bunker: started}})
}

type vaultSpec struct {
	path  string
	label string
}

func openAndRun(ctx context.Context, arguments []string) error {
	specs := make([]vaultSpec, 0, len(arguments))
	seenPath := make(map[string]struct{}, len(arguments))
	seenLabel := make(map[string]struct{}, len(arguments))
	for _, argument := range arguments {
		path, err := resolvePath(argument)
		if err != nil {
			return err
		}
		if _, ok := seenPath[path]; ok {
			return fmt.Errorf("vault path repeated: %s", path)
		}
		seenPath[path] = struct{}{}
		label, err := vaultLabel(path)
		if err != nil {
			return err
		}
		if _, ok := seenLabel[label]; ok {
			return fmt.Errorf("vault name %s is used more than once", label)
		}
		seenLabel[label] = struct{}{}
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("vault %s does not exist; run hotbox with no arguments to create one", path)
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("vault %s is not a file", path)
		}
		specs = append(specs, vaultSpec{path: path, label: label})
	}
	keys, err := keyDir()
	if err != nil {
		return err
	}
	running := make([]signer, 0, len(specs))
	defer func() {
		for _, s := range running {
			s.bunker.Close()
		}
	}()
	ports := make(map[uint16]string)
	for _, spec := range specs {
		password, err := unlockPassword(spec.label)
		if err != nil {
			return err
		}
		state, err := vault.Open(spec.path, keys, password)
		clear(password)
		if err != nil {
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		if err := claimPorts(ports, spec.label, state.WSPort, state.WSSPort); err != nil {
			state.Wipe()
			return err
		}
		npub, err := npubFromSecret(state.Secret)
		if err != nil {
			state.Wipe()
			return err
		}
		ws, wss, err := listenVault(state)
		if err != nil {
			state.Wipe()
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		started, err := bunker.Start(ctx, state.Secret, state.Connect, state.Token, ws, wss, nil)
		state.Wipe()
		if err != nil {
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		running = append(running, signer{label: spec.label, npub: npub, bunker: started})
	}
	for _, s := range running {
		fmt.Fprintf(os.Stderr, "hotbox: [%s] %s\n", s.label, s.npub)
	}
	return serve(running)
}

type signer struct {
	label  string
	npub   string
	bunker *bunker.Bunker
}

func serve(running []signer) error {
	defer func() {
		for _, s := range running {
			s.bunker.Close()
		}
	}()
	for _, s := range running {
		fmt.Printf("[%s] SIGN_WITH='%s'\n", s.label, s.bunker.URL())
	}
	fmt.Fprintln(os.Stderr, "local ws and wss only; interrupt to lock")
	if err := notifyReady(); err != nil {
		return err
	}
	errc := make(chan error, len(running))
	for _, s := range running {
		go func(b *bunker.Bunker) { errc <- b.Wait() }(s.bunker)
	}
	first := <-errc
	for _, s := range running {
		s.bunker.Close()
	}
	errs := []error{first}
	for range len(running) - 1 {
		errs = append(errs, <-errc)
	}
	return errors.Join(errs...)
}

func listenVault(state vault.State) (net.Listener, net.Listener, error) {
	wsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.WSPort))
	if err != nil {
		return nil, nil, fmt.Errorf("listen on 127.0.0.1:%d: %w", state.WSPort, err)
	}
	wssLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.WSSPort))
	if err != nil {
		_ = wsLn.Close()
		return nil, nil, fmt.Errorf("listen on 127.0.0.1:%d: %w", state.WSSPort, err)
	}
	return wsLn, wssLn, nil
}

const (
	keyDirEnv         = "HOTBOX_KEYS"
	defaultKeyDirHelp = "~/.local/share/hotbox"
)

// keyDir is where vault key files live: $HOTBOX_KEYS, or ~/.local/share/hotbox.
func keyDir() (string, error) {
	if value := os.Getenv(keyDirEnv); strings.TrimSpace(value) != "" {
		return resolvePath(value)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w (set %s to a key directory)", err, keyDirEnv)
	}
	return filepath.Join(home, ".local", "share", "hotbox"), nil
}

func resolvePath(argument string) (string, error) {
	argument = strings.TrimSpace(argument)
	if argument == "" {
		return "", errors.New("vault path is required")
	}
	if argument == "~" || strings.HasPrefix(argument, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if argument == "~" {
			argument = home
		} else {
			argument = filepath.Join(home, argument[2:])
		}
	}
	abs, err := filepath.Abs(argument)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func vaultLabel(path string) (string, error) {
	label := strings.TrimSuffix(filepath.Base(path), ".hotbox")
	if label == "" || label == "." || label == string(filepath.Separator) {
		return "", errors.New("vault path is invalid")
	}
	if strings.ContainsAny(label, "[]\r\n") {
		return "", fmt.Errorf("vault name %q is invalid", label)
	}
	return label, nil
}

func claimPorts(used map[uint16]string, label string, ports ...uint16) error {
	claimed := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if _, ok := claimed[port]; ok {
			return fmt.Errorf("vault %s repeats port %d", label, port)
		}
		if other, ok := used[port]; ok {
			return fmt.Errorf("vault %s port %d is already used by %s", label, port, other)
		}
		claimed[port] = struct{}{}
	}
	for port := range claimed {
		used[port] = label
	}
	return nil
}

func npubFromSecret(secret [32]byte) (string, error) {
	pub, err := nostr.GetPublicKey(hex.EncodeToString(secret[:]))
	if err != nil {
		return "", err
	}
	npub, err := nip19.EncodePublicKey(pub)
	if err != nil {
		return "", err
	}
	return npub, nil
}

func secretFromInput(value string) ([32]byte, error) {
	var secret [32]byte
	hexKey, err := decodeNsec(strings.TrimSpace(value))
	if err != nil {
		return secret, err
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != len(secret) {
		return secret, errors.New("invalid Nostr private key")
	}
	copy(secret[:], raw)
	return secret, nil
}

func decodeNsec(value string) (string, error) {
	if strings.HasPrefix(value, "nsec1") {
		prefix, decoded, err := nip19.Decode(value)
		if err != nil {
			return "", err
		}
		if prefix != "nsec" {
			return "", errors.New("expected an nsec")
		}
		hexKey, ok := decoded.(string)
		if !ok || len(hexKey) != 64 {
			return "", errors.New("invalid nsec")
		}
		return hexKey, nil
	}
	if len(value) != 64 {
		return "", errors.New("expected an nsec or 32-byte hex private key")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("invalid Nostr private key")
	}
	if _, err := nostr.GetPublicKey(value); err != nil {
		return "", errors.New("invalid Nostr private key")
	}
	return value, nil
}

func ask(title, description string, secret bool, validate func(string) error) (string, error) {
	var value string
	input := huh.NewInput().Title(title).Description(description).Value(&value).Validate(validate)
	if secret {
		input = input.EchoMode(huh.EchoModePassword)
	}
	if err := input.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func askNewPassword() (string, error) {
	password, err := ask("Vault password", "At least 12 characters", true, strongPassword)
	if err != nil {
		return "", err
	}
	confirm, err := ask("Confirm password", "Repeat the vault password", true, strongPassword)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(confirm)) != 1 {
		return "", errors.New("passwords do not match")
	}
	return password, nil
}

func required(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("this value is required")
	}
	return nil
}

func validNsec(value string) error {
	_, err := decodeNsec(strings.TrimSpace(value))
	return err
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

func tcpPort(ln net.Listener) (uint16, error) {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 || addr.Port > 65535 {
		return 0, errors.New("listener is not a TCP port")
	}
	return uint16(addr.Port), nil
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
