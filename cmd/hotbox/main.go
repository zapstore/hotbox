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
	if len(os.Args) == 2 && (os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help") {
		fmt.Fprint(os.Stdout, `Usage:
  hotbox
      Create a vault. Asks for a name, an nsec, and a password, prints the npub, then runs the bunker.
  hotbox <vault>
      Unlock that vault and run the bunker.
      On a terminal, asks for the password. Otherwise reads one line from stdin.
      Prints SIGN_WITH='bunker://…' for zsp and other NIP-46 clients.
      Under systemd Type=notify, signals ready after the vault unlocks.

The bunker listens on 127.0.0.1 only, with ws and wss, and does not dial the network.
`)
		return nil
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch len(os.Args) {
	case 1:
		return createAndRun(ctx)
	case 2:
		return openAndRun(ctx, os.Args[1])
	default:
		return errors.New("usage: hotbox [vault]")
	}
}

func createAndRun(ctx context.Context) error {
	name, err := ask("Vault name", "Stored in ~/.hotbox, for example: zapstore", false, required)
	if err != nil {
		return err
	}
	path, err := vaultPath(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault %s already exists; run hotbox %s", path, strings.TrimSuffix(name, ".hotbox"))
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
	if err := vault.Create(path, password, state); err != nil {
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
	fmt.Fprintf(os.Stderr, "created %s\n%s\n", path, npub)
	return serve(ctx, state, wsLn, wssLn)
}

func openAndRun(ctx context.Context, argument string) error {
	path, err := resolve(argument)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vault %s does not exist; run hotbox with no arguments to create one", path)
		}
		return err
	}
	password, err := unlockPassword()
	if err != nil {
		return err
	}
	state, err := vault.Open(path, password)
	if err != nil {
		return err
	}
	defer state.Wipe()
	npub, err := npubFromSecret(state.Secret)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "hotbox: %s\n", npub)
	wsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.WSPort))
	if err != nil {
		return fmt.Errorf("listen on 127.0.0.1:%d: %w", state.WSPort, err)
	}
	wssLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.WSSPort))
	if err != nil {
		_ = wsLn.Close()
		return fmt.Errorf("listen on 127.0.0.1:%d: %w", state.WSSPort, err)
	}
	return serve(ctx, state, wsLn, wssLn)
}

func serve(ctx context.Context, state vault.State, wsLn, wssLn net.Listener) error {
	session, err := bunker.Start(ctx, state.Secret, state.Connect, state.Token, wsLn, wssLn)
	if err != nil {
		return err
	}
	defer session.Close()
	fmt.Printf("SIGN_WITH='%s'\n", session.URL())
	fmt.Fprintln(os.Stderr, "local ws and wss only; interrupt to lock")
	if err := notifyReady(); err != nil {
		return err
	}
	return session.Wait()
}

func vaultPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return "", errors.New("vault name must not contain a directory")
	}
	if !strings.HasSuffix(name, ".hotbox") {
		name += ".hotbox"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".hotbox", name), nil
}

func resolve(argument string) (string, error) {
	if !filepath.IsAbs(argument) && !strings.ContainsRune(argument, filepath.Separator) {
		named, err := vaultPath(argument)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(named); err == nil {
			return named, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return filepath.Abs(argument)
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
}
