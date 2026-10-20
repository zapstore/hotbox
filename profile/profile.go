// Package profile stores one bunker identity in a vaultcore container.
//
// The Nostr key is profiles/<name>/nsec, marked secret, so the only read path
// is Vault.Use. An Android key is optional. When present it is
// profiles/<name>/android-key, also secret. The connect secret, token, and
// ports are profiles/<name>/bunker. The certificate chain and signing PIN are
// profiles/<name>/android. Key and Android.Use decrypt a key only for the callback.
package profile

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr/nip19"
	"vaultcore/vault"
)

const bunkerSize = 1 + 32 + 16 + 2 + 2

var errCorrupt = errors.New("unsupported or corrupt profile")

// Profile is one bunker identity in an open container.
// Key decrypts the private key for the duration of the callback.
// Connect and Token are the bunker capability; call Wipe after copying them.
type Profile struct {
	Name    string
	Connect [32]byte
	Token   [16]byte
	WSPort  uint16
	WSSPort uint16
	Npub    string
	Key     func(context.Context, func([]byte) error) error
	Android Android
}

// Wipe clears the capability fields. It does not affect Key.
func (p *Profile) Wipe() {
	if p == nil {
		return
	}
	p.Connect = [32]byte{}
	p.Token = [16]byte{}
	p.Android.Wipe()
	runtime.KeepAlive(p)
}

// Create seals a new single-file container holding one profile and returns it open.
// secret is the 32-byte Nostr private key. The caller wipes secret and password.
// keyFile is the key path. It is empty when opts select the keychain or no key file.
// android is sealed in the same call when it is set. The zero value seals only
// the nsec. There is no later way to add or replace an Android key.
func Create(ctx context.Context, path, keyFile, name string, password, secret []byte, connect [32]byte, token [16]byte, wsPort, wssPort uint16, android AndroidKey, opts ...vaultcore.Option) (*vaultcore.Vault, Profile, error) {
	if err := validName(name); err != nil {
		return nil, Profile{}, err
	}
	if err := validBunker(connect, token, wsPort, wssPort); err != nil {
		return nil, Profile{}, err
	}
	if err := validSecret(secret); err != nil {
		return nil, Profile{}, err
	}
	if !androidOmitted(android) {
		if err := validAndroid(android); err != nil {
			return nil, Profile{}, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, Profile{}, err
	}
	opts = append([]vaultcore.Option{vaultcore.SingleFile()}, opts...)
	v, err := vaultcore.Create(ctx, path, keyFile, password, opts...)
	if err != nil {
		return nil, Profile{}, err
	}
	ok := false
	defer func() {
		if !ok {
			abandon(v, path)
		}
	}()
	if err := v.Add(ctx, nsecPath(name), bytes.NewReader(secret), true); err != nil {
		return nil, Profile{}, err
	}
	body := encodeBunker(connect, token, wsPort, wssPort)
	defer wipe(body)
	if err := v.Add(ctx, bunkerPath(name), bytes.NewReader(body), false); err != nil {
		return nil, Profile{}, err
	}
	if !androidOmitted(android) {
		meta, err := encodeAndroid(android)
		if err != nil {
			return nil, Profile{}, err
		}
		defer wipe(meta)
		if err := v.Add(ctx, androidPath(name), bytes.NewReader(meta), false); err != nil {
			return nil, Profile{}, err
		}
		if err := v.Add(ctx, androidKeyPath(name), bytes.NewReader(android.PKCS8), true); err != nil {
			return nil, Profile{}, err
		}
	}
	p, err := load(ctx, v, name)
	if err != nil {
		return nil, Profile{}, err
	}
	ok = true
	return v, p, nil
}

// Open unlocks a container and loads its single profile.
// A new vault is one file. A directory container from an older hotbox still opens.
// The caller must close the vault. A second writer gets vaultcore.ErrBusy.
// When the nsec or Android key blob is gone, Open returns vaultcore.ErrMissing
// and names that path. It leaves the entry in place.
func Open(ctx context.Context, path, keyFile string, password []byte, opts ...vaultcore.Option) (*vaultcore.Vault, Profile, error) {
	v, err := vaultcore.Open(ctx, path, keyFile, password, opts...)
	if err != nil {
		return nil, Profile{}, err
	}
	name, err := findProfile(v)
	if err != nil {
		_ = v.Close()
		return nil, Profile{}, err
	}
	p, err := load(ctx, v, name)
	if err != nil {
		_ = v.Close()
		return nil, Profile{}, err
	}
	return v, p, nil
}

func load(ctx context.Context, v *vaultcore.Vault, name string) (Profile, error) {
	if err := confirmSecret(v, name); err != nil {
		return Profile{}, err
	}
	connect, token, ws, wss, err := readBunker(ctx, v, name)
	if err != nil {
		return Profile{}, err
	}
	alias, pin, certs, err := readAndroid(ctx, v, name)
	if err != nil {
		return Profile{}, err
	}
	if err := refuseMissingKeys(ctx, v, name, certs != nil); err != nil {
		return Profile{}, err
	}
	var gate sync.Mutex
	p := Profile{
		Name:    name,
		Connect: connect,
		Token:   token,
		WSPort:  ws,
		WSSPort: wss,
		Key: func(ctx context.Context, fn func([]byte) error) error {
			gate.Lock()
			defer gate.Unlock()
			return v.Use(ctx, nsecPath(name), fn)
		},
	}
	if certs != nil {
		p.Android = Android{
			Alias: alias,
			PIN:   pin,
			Certs: certs,
			Use: func(ctx context.Context, fn func([]byte) error) error {
				gate.Lock()
				defer gate.Unlock()
				return v.Use(ctx, androidKeyPath(name), fn)
			},
		}
	}
	if err := p.Key(ctx, func(key []byte) error {
		pub, err := pubkey(key)
		if err != nil {
			return err
		}
		npub, err := nip19.EncodePublicKey(pub)
		if err != nil {
			return err
		}
		p.Npub = npub
		return nil
	}); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// refuseMissingKeys reports secret profile paths whose blob is not on disk.
// Other missing entries stay as they are. Repair would delete the key, so this does not call it.
func refuseMissingKeys(ctx context.Context, v *vaultcore.Vault, name string, android bool) error {
	st, err := v.Status(ctx)
	if err != nil {
		return err
	}
	if st.Missing == 0 {
		return nil
	}
	paths := []string{nsecPath(name)}
	if android {
		paths = append(paths, androidKeyPath(name))
	}
	var gone []string
	for _, path := range paths {
		err := v.Use(ctx, path, func([]byte) error { return nil })
		if errors.Is(err, vaultcore.ErrMissing) {
			gone = append(gone, path)
			continue
		}
		if err != nil {
			return err
		}
	}
	if len(gone) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", strings.Join(gone, ", "), vaultcore.ErrMissing)
}

func confirmSecret(v *vaultcore.Vault, name string) error {
	entries, err := v.List("profiles/" + name)
	if err != nil {
		return err
	}
	var nsec, hasKey, keySecret, hasMeta, metaSecret bool
	for _, e := range entries {
		if e.Dir {
			continue
		}
		switch e.Name {
		case "nsec":
			nsec = e.Secret
		case "android-key":
			hasKey = true
			keySecret = e.Secret
		case "android":
			hasMeta = true
			metaSecret = e.Secret
		}
	}
	if !nsec {
		return errors.New("nsec entry is missing or not secret")
	}
	if hasKey != hasMeta || (hasKey && (!keySecret || metaSecret)) {
		return errors.New("android signing key is missing or not secret")
	}
	return nil
}

func findProfile(v *vaultcore.Vault) (string, error) {
	entries, err := v.List("profiles")
	if err != nil {
		return "", err
	}
	var name string
	for _, e := range entries {
		if !e.Dir {
			return "", errCorrupt
		}
		if name != "" {
			return "", errors.New("vault has more than one profile")
		}
		name = e.Name
	}
	if name == "" {
		return "", errors.New("vault has no profile")
	}
	if err := validName(name); err != nil {
		return "", err
	}
	return name, nil
}

func readBunker(ctx context.Context, v *vaultcore.Vault, name string) (connect [32]byte, token [16]byte, ws, wss uint16, err error) {
	var w capWriter
	w.max = bunkerSize
	if err = v.Cat(ctx, bunkerPath(name), &w); err != nil {
		if errors.Is(err, vaultcore.ErrNotFound) {
			err = errors.New("profile bunker entry is missing")
		}
		return
	}
	defer wipe(w.buf)
	if len(w.buf) != bunkerSize || w.buf[0] != 1 {
		err = errCorrupt
		return
	}
	copy(connect[:], w.buf[1:33])
	copy(token[:], w.buf[33:49])
	ws = binary.BigEndian.Uint16(w.buf[49:51])
	wss = binary.BigEndian.Uint16(w.buf[51:53])
	err = validBunker(connect, token, ws, wss)
	return
}

type capWriter struct {
	buf []byte
	max int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if len(w.buf)+len(p) > w.max {
		return 0, errCorrupt
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func encodeBunker(connect [32]byte, token [16]byte, ws, wss uint16) []byte {
	buf := make([]byte, bunkerSize)
	buf[0] = 1
	copy(buf[1:33], connect[:])
	copy(buf[33:49], token[:])
	binary.BigEndian.PutUint16(buf[49:51], ws)
	binary.BigEndian.PutUint16(buf[51:53], wss)
	return buf
}

func readAndroid(ctx context.Context, v *vaultcore.Vault, name string) (alias string, pin [32]byte, certs [][]byte, err error) {
	var w capWriter
	w.max = maxAndroidMeta
	if err = v.Cat(ctx, androidPath(name), &w); err != nil {
		if errors.Is(err, vaultcore.ErrNotFound) {
			err = nil
		}
		return
	}
	defer wipe(w.buf)
	return decodeAndroid(w.buf)
}

func nsecPath(name string) string   { return "profiles/" + name + "/nsec" }
func bunkerPath(name string) string { return "profiles/" + name + "/bunker" }

func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00[]\r\n") {
		return fmt.Errorf("profile name %q is invalid", name)
	}
	return nil
}

func validBunker(connect [32]byte, token [16]byte, ws, wss uint16) error {
	if connect == [32]byte{} || token == [16]byte{} {
		return errors.New("bunker secret is missing")
	}
	if ws == 0 || wss == 0 || ws == wss {
		return errors.New("bunker ports are invalid")
	}
	return nil
}

func validSecret(secret []byte) error {
	if _, err := pubkey(secret); err != nil {
		return err
	}
	return nil
}

func pubkey(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("invalid Nostr private key")
	}
	priv, pub := btcec.PrivKeyFromBytes(key)
	defer priv.Zero()
	compressed := pub.SerializeCompressed()
	if len(compressed) != 33 {
		return "", errors.New("invalid Nostr private key")
	}
	return hex.EncodeToString(compressed[1:]), nil
}

func abandon(v *vaultcore.Vault, path string) {
	if v == nil {
		_ = os.RemoveAll(path)
		return
	}
	key := v.KeyFile()
	_ = v.Close()
	_ = os.RemoveAll(path)
	_ = os.Remove(path + ".lock")
	_ = os.Remove(path + ".writing")
	if key != "" {
		_ = os.Remove(key)
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
