package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"github.com/zapstore/hotbox/keystore"
	"github.com/zapstore/hotbox/profile"
	"github.com/zapstore/hotbox/token"
	"vaultcore/vault"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hotbox:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "sign" {
		return runSign(os.Args[2:])
	}
	vaults, createKey, help, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if help {
		fmt.Fprint(os.Stdout, `Usage:
  hotbox [--key file]
      Create a vault. Asks for a path, where to keep the key, an nsec, a password, and an optional Android keystore, prints the npub, then runs the bunker.
      Leave the nsec empty to generate one. Leave the password empty for no passphrase.
  hotbox [--key file] <vault> [--key file] <vault> ...
      Unlock each vault and run a bunker for each.
      A vault is a file whose name ends in .hotbox. If you omit that suffix, it is added.
      A directory vault from an older hotbox still opens.
      A relative path is taken from the working directory. A leading ~/ is expanded.
      A vault named sign must be given as ./sign.
  hotbox sign <app-unsigned.apk>...
      Sign APKs with a running hotbox. See hotbox sign --help.

The Nostr key is stored at profiles/<name>/nsec and marked secret. Leave the
nsec prompt empty to generate one. A generated key is not printed. An Android
keystore is optional. When one is given, the private key is stored at
profiles/<name>/android-key and marked secret. Each signature decrypts a key
only for that call. The keystore is read once, at creation; there is no
command to add or replace it. Connect secret, token, and ports are stored at
profiles/<name>/bunker. The certificate chain and signing PIN are stored at
profiles/<name>/android.

Creation asks for the macOS keychain, a key file, or the passphrase alone.
The keychain is preselected when this machine has one. A key file defaults
to <name>.key in $HOTBOX_KEYS, or `+defaultKeyDirHelp+` when that is unset.
name is the vault name, so zapstore.hotbox uses zapstore.key.
--key sets the file for the next vault only, and that vault uses a file:

  hotbox zapstore releases
  hotbox --key /path/to/zapstore.key zapstore --key /path/to/releases.key releases

With no --key, a Mac looks in the keychain first and then the default key
file. A vault with no key file opens with the passphrase alone.

Neither the nsec nor a key file or keychain entry can be recovered from the
vault. If one is lost, create a new vault from your nsec.

Connections and signature attempts are logged to stderr. The bunker URL and
the private key are not logged.

On a terminal, asks for each vault password. An empty password unlocks a
vault that was created with an empty passphrase. When stdin is not a terminal
(a pipe, or a service that passes passwords on stdin), reads one line per
vault, in the same order as the paths. An empty line is an empty password.
Creation prints the key, then one .env block: SIGN_WITH, plus HOTBOX_PIN
and HOTBOX_SOCKET when the vault has an Android key. A key file prints its
path. The keychain prints "Keychain value to back up" and the output of
security find-generic-password -w. That hex is what to back up, and
xxd -r -p turns it into a key file for --key. An empty passphrase with the
keychain or a key file uses that secret alone. Opening vaults prints the
.env block for each, prefixed with [name]. Paste a block into the project
.env as is.
The socket and the PKCS#11 config are /tmp/hotbox-<uid>/<name>.sock and
.pkcs11.cfg, and they stay the same across runs. The key alias is always hotbox.
The PKCS#11 module asks hotbox to sign and never receives the private key.
The socket also signs NIP-C1 certificate proofs, only for the vault's npub.
Under systemd Type=notify, signals ready after every vault is listening.

The bunker listens on 127.0.0.1 only, with ws and wss, and does not dial the network.
The Android signer listens on a Unix socket in /tmp and accepts only this user.
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
	raw, err := ask("Vault path", "File name. .hotbox is added if you leave it off. A relative path is taken from the working directory.", false, required)
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
	choice, err := askKeyStorage()
	if err != nil {
		return err
	}
	keyFile, opts, err := createKeyArgs(choice, key, path)
	if err != nil {
		return err
	}
	nsec, err := ask("Nostr private key", "nsec1… or 64-character hex. Leave empty to generate one. It is sealed inside the vault.", true, validNsec)
	if err != nil {
		return err
	}
	password, err := askNewPassword()
	if err != nil {
		return err
	}
	if password == "" && choice == noneChoice {
		status("no passphrase and no key file; anyone with this vault can unlock it")
	}
	secret, err := secretFromInput(nsec)
	if err != nil {
		return err
	}
	defer clear(secret[:])
	if nsec == "" {
		npub, err := npubFromSecret(secret[:])
		if err != nil {
			return err
		}
		status("Generated a new Nostr key %s", npub)
	}
	pw := []byte(password)
	defer clear(pw)
	android, err := readAndroidKey()
	if err != nil {
		return err
	}
	defer clear(android.PKCS8)

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
	v, prof, err := profile.Create(ctx, path, keyFile, label, pw, secret[:], connect, token, wsPort, wssPort, android, opts...)
	if err != nil {
		return err
	}
	defer v.Close()
	if err := reportKey(v); err != nil {
		return err
	}
	tok, err := startToken(ctx, prof, log)
	if err != nil {
		prof.Wipe()
		return err
	}
	running, err := bunker.Start(ctx, prof.Key, prof.Connect, prof.Token, wsLn, wssLn, nil, log)
	prof.Wipe()
	if err != nil {
		tok.Close()
		return err
	}
	started = true
	return serve([]signer{{label: label, bunker: running, token: tok}}, false)
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
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("vault %s is not a container", path)
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
			s.token.Close()
		}
	}()
	ports := make(map[uint16]string)
	for _, spec := range specs {
		password, err := unlockPassword(spec.label)
		if err != nil {
			return err
		}
		keyFile, opts, err := openKeyArgs(spec.key, spec.path)
		if err != nil {
			return err
		}
		v, prof, err := profile.Open(ctx, spec.path, keyFile, password, opts...)
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
		tok, err := startToken(ctx, prof, log)
		if err != nil {
			prof.Wipe()
			_ = ws.Close()
			_ = wss.Close()
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		started, err := bunker.Start(ctx, prof.Key, prof.Connect, prof.Token, ws, wss, nil, log)
		prof.Wipe()
		if err != nil {
			tok.Close()
			return fmt.Errorf("%s: %w", spec.label, err)
		}
		running = append(running, signer{label: spec.label, bunker: started, token: tok})
	}
	return serve(running, true)
}

// reportKey prints where to find the secret that opens the vault.
// A key file prints its path. The keychain prints "Keychain value to back up"
// and the same text `security find-generic-password -w` returns: the key in
// hex, not the vault id.
func reportKey(v *vaultcore.Vault) error {
	line, err := keyReport(v)
	if err != nil || line == "" {
		return err
	}
	status("%s", line)
	return nil
}

func keyReport(v *vaultcore.Vault) (string, error) {
	stored := v.KeyStorage()
	switch stored.Kind {
	case vaultcore.KeyInFile:
		return "key " + stored.Location, nil
	case vaultcore.KeyInKeychain:
		raw, err := v.KeyCopy()
		if err != nil || len(raw) == 0 {
			if err == nil {
				err = errors.New("key is empty")
			}
			return "", fmt.Errorf("read keychain key %s: %w", stored.Location, err)
		}
		defer clear(raw)
		return "Keychain value to back up: " + hex.EncodeToString(raw), nil
	default:
		return "", nil
	}
}

// envBlock is the .env text for one vault, printed once to stdout.
// prefix is set when opening vaults. Creation prints a single block with no name.
func envBlock(label string, prefix bool, signWith, pin, socket string) string {
	var b strings.Builder
	if prefix {
		fmt.Fprintf(&b, "[%s]\n", label)
	}
	fmt.Fprintf(&b, "SIGN_WITH='%s'\n", signWith)
	if pin != "" {
		fmt.Fprintf(&b, "HOTBOX_PIN='%s'\n", pin)
		fmt.Fprintf(&b, "HOTBOX_SOCKET='%s'\n", socket)
	}
	return b.String()
}

type signer struct {
	label  string
	bunker *bunker.Bunker
	token  *token.Token
}

func serve(running []signer, prefix bool) error {
	defer func() {
		for _, s := range running {
			s.bunker.Close()
			s.token.Close()
		}
	}()
	for i, s := range running {
		if i > 0 {
			fmt.Println()
		}
		pin, socket := "", ""
		if s.token != nil {
			pin, socket = s.token.Pin(), s.token.Path
		}
		fmt.Print(envBlock(s.label, prefix, s.bunker.URL(), pin, socket))
		if s.token != nil && s.token.Config == "" {
			status("pkcs11 module is not next to the hotbox binary; rebuild with make")
		}
	}
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

func startToken(ctx context.Context, prof profile.Profile, log *slog.Logger) (*token.Token, error) {
	if prof.Android.Use == nil {
		return nil, nil
	}
	prefix, decoded, err := nip19.Decode(prof.Npub)
	pubkey, ok := decoded.(string)
	if err != nil || prefix != "npub" || !ok {
		return nil, errors.New("profile npub is invalid")
	}
	return token.Start(ctx, prof.Name, token.Key{
		Alias:  prof.Android.Alias,
		PIN:    prof.Android.PIN,
		Certs:  prof.Android.Certs,
		Pubkey: pubkey,
		Use:    prof.Android.Use,
	}, token.LibraryPath(), log)
}

func readAndroidKey() (profile.AndroidKey, error) {
	raw, err := askPath("Android keystore", "Optional. Leave empty to seal only the nsec. Otherwise JKS, PKCS#12, or unencrypted PEM. The file is not kept. Tab completes directories and keystores.")
	if err != nil {
		return profile.AndroidKey{}, err
	}
	if strings.TrimSpace(raw) == "" {
		return profile.AndroidKey{}, nil
	}
	path, err := resolvePath(raw)
	if err != nil {
		return profile.AndroidKey{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return profile.AndroidKey{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return profile.AndroidKey{}, err
	}
	if info.IsDir() {
		return profile.AndroidKey{}, errors.New("keystore path is a directory")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return profile.AndroidKey{}, err
	}
	defer clear(data)
	if len(data) > 1<<20 {
		return profile.AndroidKey{}, errors.New("keystore is too large")
	}
	store, err := ask("Keystore password", "Store password. Empty for an unencrypted PEM.", true, allowEmpty)
	if err != nil {
		return profile.AndroidKey{}, err
	}
	entries, err := keystore.Parse(data, store, "")
	if errors.Is(err, keystore.ErrKeyPassword) {
		keyPass, askErr := ask("Key password", "Password for the private key.", true, required)
		if askErr != nil {
			return profile.AndroidKey{}, askErr
		}
		entries, err = keystore.Parse(data, store, keyPass)
	}
	if err != nil {
		return profile.AndroidKey{}, err
	}
	alias, err := askAlias(entries)
	if err != nil {
		for i := range entries {
			clear(entries[i].PKCS8)
		}
		return profile.AndroidKey{}, err
	}
	var chosen *keystore.Entry
	for i := range entries {
		if entries[i].Alias == alias {
			chosen = &entries[i]
			continue
		}
		clear(entries[i].PKCS8)
	}
	if chosen == nil {
		return profile.AndroidKey{}, errors.New("keystore alias is missing")
	}
	leaf, err := x509.ParseCertificate(chosen.Certs[0])
	if err != nil {
		clear(chosen.PKCS8)
		return profile.AndroidKey{}, err
	}
	sum := sha256.Sum256(leaf.Raw)
	var fp strings.Builder
	for i, b := range sum {
		if i > 0 {
			fp.WriteByte(':')
		}
		fmt.Fprintf(&fp, "%02X", b)
	}
	if err := askConfirm("Seal this certificate?", leaf.Subject.String()+"\nSHA-256 "+fp.String()); err != nil {
		clear(chosen.PKCS8)
		return profile.AndroidKey{}, err
	}
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		clear(chosen.PKCS8)
		return profile.AndroidKey{}, err
	}
	var pin [32]byte
	hex.Encode(pin[:], seed[:])
	return profile.AndroidKey{Alias: profile.AndroidAlias, PIN: pin, PKCS8: chosen.PKCS8, Certs: chosen.Certs}, nil
}

func askAlias(entries []keystore.Entry) (string, error) {
	if len(entries) == 1 {
		return entries[0].Alias, nil
	}
	opts := make([]huh.Option[string], len(entries))
	for i, entry := range entries {
		opts[i] = huh.NewOption(entry.Alias, entry.Alias)
	}
	choice := entries[0].Alias
	err := huh.NewSelect[string]().
		Title("Key alias").
		Description("Which key to seal. Signing always uses the name hotbox.").
		Options(opts...).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

func askConfirm(title, description string) error {
	yes := true
	err := huh.NewConfirm().
		Title(title).
		Description(description).
		Affirmative("Seal").
		Negative("Cancel").
		Value(&yes).
		Run()
	if err != nil {
		return err
	}
	if !yes {
		return errors.New("certificate was not sealed")
	}
	return nil
}

func allowEmpty(string) error { return nil }

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

	keychainChoice = "keychain"
	fileChoice     = "file"
	noneChoice     = "none"
)

// askKeyStorage offers the keychain, a key file, or the passphrase alone.
// The keychain is the initial selection when this machine has one.
func askKeyStorage() (string, error) {
	choice := fileChoice
	if vaultcore.KeychainSupported() {
		choice = keychainChoice
	}
	err := huh.NewSelect[string]().
		Title("Key storage").
		Description("A second secret kept outside the vault, or the passphrase alone.").
		Options(
			huh.NewOption("macOS keychain", keychainChoice),
			huh.NewOption("Key file", fileChoice),
			huh.NewOption("Passphrase only", noneChoice),
		).
		Value(&choice).
		Run()
	if err != nil {
		return "", err
	}
	return choice, nil
}

// createKeyArgs maps a creation choice to the key path and Create options.
// explicit is the --key path and applies only to a key file.
func createKeyArgs(choice, explicit, vaultPath string) (string, []vaultcore.Option, error) {
	switch choice {
	case keychainChoice, noneChoice:
		if strings.TrimSpace(explicit) != "" {
			return "", nil, errors.New("--key applies only when the key is stored in a file")
		}
		if choice == keychainChoice {
			return "", []vaultcore.Option{vaultcore.Keychain()}, nil
		}
		return "", []vaultcore.Option{vaultcore.NoKeyFile()}, nil
	case fileChoice:
		path, err := vaultKey(vaultPath, explicit)
		return path, nil, err
	default:
		return "", nil, errors.New("key storage choice is invalid")
	}
}

// openKeyArgs is the key path and options for Open. An explicit --key uses
// only that file. Otherwise a Mac tries the keychain and falls back to the
// default key file.
func openKeyArgs(explicit, vaultPath string) (string, []vaultcore.Option, error) {
	if strings.TrimSpace(explicit) != "" {
		path, err := resolvePath(explicit)
		return path, nil, err
	}
	var opts []vaultcore.Option
	if vaultcore.KeychainSupported() {
		opts = []vaultcore.Option{vaultcore.Keychain()}
	}
	path, err := vaultKey(vaultPath, "")
	if err != nil && len(opts) > 0 {
		return "", opts, nil
	}
	return path, opts, err
}

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
	value = strings.TrimSpace(value)
	if value == "" {
		return generateSecret()
	}
	var secret [32]byte
	hexKey, err := decodeNsec(value)
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
	password, err := ask("Vault password", "At least 12 characters, or leave empty.", true, strongPassword)
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

func npubFromSecret(secret []byte) (string, error) {
	if len(secret) != 32 {
		return "", errors.New("invalid Nostr private key")
	}
	pub, err := nostr.GetPublicKey(hex.EncodeToString(secret))
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}
	npub, err := nip19.EncodePublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("npub: %w", err)
	}
	return npub, nil
}

func generateSecret() ([32]byte, error) {
	var secret [32]byte
	hexKey := nostr.GeneratePrivateKey()
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != len(secret) {
		clear(raw)
		return secret, errors.New("could not generate a Nostr private key")
	}
	copy(secret[:], raw)
	clear(raw)
	if _, err := nostr.GetPublicKey(hexKey); err != nil {
		clear(secret[:])
		return [32]byte{}, errors.New("could not generate a Nostr private key")
	}
	return secret, nil
}

func validNsec(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	_, err := decodeNsec(value)
	return err
}

func strongPassword(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
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
