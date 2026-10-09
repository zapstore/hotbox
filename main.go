package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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

	"github.com/zapstore/hotbox/bunker"
	"github.com/zapstore/hotbox/profile"
	"vaultcore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hotbox:", err)
		os.Exit(1)
	}
}

func run() error {
	vaults, createKey, help, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if help {
		fmt.Fprint(os.Stdout, `Usage:
  hotbox [--key file]
      Create a vault. Asks for a path, an nsec, and a password, prints the npub, then runs the bunker.
  hotbox [--key file] <vault> [--key file] <vault> ...
      Unlock each vault and run a bunker for each.
      A vault is a directory whose name ends in .hotbox. If you omit that suffix, it is added.
      A relative path is taken from the working directory. A leading ~/ is expanded.

The private key is stored at profiles/<name>/nsec and marked secret. Signing
decrypts it only for the duration of the signature. Connect secret, token, and
ports are stored at profiles/<name>/bunker.

The key file defaults to <name>.key in $HOTBOX_KEYS, or `+defaultKeyDirHelp+` when that
is unset. name is the vault name, so zapstore.hotbox uses zapstore.key.
--key sets the file for the next vault only:

  hotbox zapstore releases
  hotbox --key /path/to/zapstore.key zapstore --key /path/to/releases.key releases

Neither the nsec nor the key file can be recovered from the vault. If one is
lost, create a new vault from your nsec.

Connections and signature attempts are logged to stderr. The bunker URL and
the private key are not logged.

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
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if len(vaults) == 0 {
		err = createAndRun(ctx, log, createKey)
	} else {
		err = openAndRun(ctx, vaults, log)
	}
	if err != nil {
		log.Error("stopped", "err", err.Error())
	} else {
		log.Info("stopped")
	}
	return err
}

// cliVault is one container argument. key is empty when the vault uses its default file.
type cliVault struct {
	arg string
	key string
}

func parseArgs(args []string) (vaults []cliVault, createKey string, help bool, err error) {
	var pending string
	var haveKey bool
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			help = true
		case arg == "help" && len(args) == 1:
			help = true
		case arg == "--key" && i+1 < len(args):
			if haveKey {
				return nil, "", false, errors.New("--key was given twice before a vault")
			}
			i++
			pending = args[i]
			haveKey = true
		case arg == "--key":
			return nil, "", false, errors.New("--key requires a file path")
		case strings.HasPrefix(arg, "-"):
			return nil, "", false, fmt.Errorf("unknown flag %s", arg)
		default:
			key := ""
			if haveKey {
				key = pending
				haveKey = false
			}
			vaults = append(vaults, cliVault{arg: arg, key: key})
		}
	}
	if haveKey {
		if len(vaults) == 0 {
			return nil, pending, help, nil
		}
		return nil, "", false, errors.New("--key requires a vault")
	}
	return vaults, "", help, nil
}

func createAndRun(ctx context.Context, log *slog.Logger, key string) error {
	raw, err := ask("Vault path", "Directory name. .hotbox is added if you leave it off. A relative path is taken from the working directory.", false, required)
	if err != nil {
		return err
	}
	path, err := vaultPath(raw)
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
	pw := []byte(password)
	defer clear(pw)

	wsLn, wssLn, err := listenPair()
	if err != nil {
		return err
	}
	started := false
	defer func() {
		if !started {
			_ = wsLn.Close()
			_ = wssLn.Close()
		}
	}()
	wsPort, err := tcpPort(wsLn)
	if err != nil {
		return err
	}
	wssPort, err := tcpPort(wssLn)
	if err != nil {
		return err
	}
	var connect [32]byte
	var token [16]byte
	defer func() {
		connect = [32]byte{}
		token = [16]byte{}
		runtime.KeepAlive(&connect)
		runtime.KeepAlive(&token)
	}()
	if _, err := rand.Read(connect[:]); err != nil {
		return err
	}
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	keyFile, err := vaultKey(path, key)
	if err != nil {
		return err
	}
	v, prof, err := profile.Create(ctx, path, keyFile, label, pw, secret[:], connect, token, wsPort, wssPort)
	if err != nil {
		return err
	}
	defer v.Close()
	running, err := bunker.Start(ctx, prof.Key, prof.Connect, prof.Token, wsLn, wssLn, nil, log)
	npub := prof.Npub
	keyFile = v.KeyFile()
	prof.Wipe()
	if err != nil {
		return err
	}
	started = true
	status("created %s", path)
	status("key file %s", keyFile)
	status("open with: hotbox --key %s %s", keyFile, path)
	status("[%s] %s", label, npub)
	return serve([]signer{{label: label, bunker: running}})
}

type vaultSpec struct {
	path  string
	label string
	key   string
}

func openAndRun(ctx context.Context, vaults []cliVault, log *slog.Logger) error {
	specs := make([]vaultSpec, 0, len(vaults))
	seenPath := make(map[string]struct{}, len(vaults))
	seenLabel := make(map[string]struct{}, len(vaults))
	for _, vault := range vaults {
		path, err := vaultPath(vault.arg)
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
		if !info.IsDir() {
			return fmt.Errorf("vault %s is not a directory container", path)
		}
		specs = append(specs, vaultSpec{path: path, label: label, key: vault.key})
	}
	var opened []*vaultcore.Vault
	defer func() {
		for _, v := range opened {
			_ = v.Close()
		}
	}()
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
		keyFile, err := vaultKey(spec.path, spec.key)
		if err != nil {
			return err
		}
		v, prof, err := profile.Open(ctx, spec.path, keyFile, password)
		clear(password)
		if err != nil {
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		opened = append(opened, v)
		if err := claimPorts(ports, spec.label, prof.WSPort, prof.WSSPort); err != nil {
			prof.Wipe()
			return err
		}
		ws, wss, err := listenVault(prof.WSPort, prof.WSSPort)
		if err != nil {
			prof.Wipe()
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		started, err := bunker.Start(ctx, prof.Key, prof.Connect, prof.Token, ws, wss, nil, log)
		npub := prof.Npub
		prof.Wipe()
		if err != nil {
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		running = append(running, signer{label: spec.label, npub: npub, bunker: started})
	}
	for _, s := range running {
		status("hotbox: [%s] %s", s.label, s.npub)
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
	status("local ws and wss only; interrupt to lock")
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

func listenPair() (net.Listener, net.Listener, error) {
	wsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	wssLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = wsLn.Close()
		return nil, nil, err
	}
	return wsLn, wssLn, nil
}

func listenVault(ws, wss uint16) (net.Listener, net.Listener, error) {
	wsLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ws))
	if err != nil {
		return nil, nil, fmt.Errorf("listen on 127.0.0.1:%d: %w", ws, err)
	}
	wssLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", wss))
	if err != nil {
		_ = wsLn.Close()
		return nil, nil, fmt.Errorf("listen on 127.0.0.1:%d: %w", wss, err)
	}
	return wsLn, wssLn, nil
}

const (
	keyDirEnv         = "HOTBOX_KEYS"
	defaultKeyDirHelp = "~/.keys/hotbox"
)

// vaultKey is the key file for a vault. An explicit path is used as given.
// Otherwise the file is <name>.key in $HOTBOX_KEYS, or ~/.keys/hotbox.
func vaultKey(vaultPath, explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return resolvePath(explicit)
	}
	dir, err := keyDir()
	if err != nil {
		return "", err
	}
	label, err := vaultLabel(vaultPath)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, label+".key"), nil
}

// keyDir is where default key files live: $HOTBOX_KEYS, or ~/.keys/hotbox.
func keyDir() (string, error) {
	if value := os.Getenv(keyDirEnv); strings.TrimSpace(value) != "" {
		return resolvePath(value)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w (set %s to a key directory)", err, keyDirEnv)
	}
	return filepath.Join(home, ".keys", "hotbox"), nil
}

func vaultPath(argument string) (string, error) {
	argument = strings.TrimSpace(argument)
	argument = strings.TrimRight(argument, `/\`)
	if argument == "" {
		return "", errors.New("vault path is required")
	}
	if !strings.HasSuffix(argument, ".hotbox") {
		argument += ".hotbox"
	}
	return resolvePath(argument)
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
	return filepath.Abs(argument)
}

func vaultLabel(path string) (string, error) {
	label := filepath.Base(path)
	for _, ext := range []string{".vault", ".hotbox"} {
		if strings.HasSuffix(label, ext) {
			label = strings.TrimSuffix(label, ext)
			break
		}
	}
	if label == "" || label == "." || label == string(filepath.Separator) {
		return "", errors.New("vault path is invalid")
	}
	if strings.ContainsAny(label, "[]\r\n/\\") {
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

func status(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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
