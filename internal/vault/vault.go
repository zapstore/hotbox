// Package vault stores signing material encrypted at rest.
package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	nostr "github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	saltSize  = 16
	keySize   = chacha20poly1305.KeySize
	timeCost  = 3
	memoryKiB = 64 * 1024
	threads   = 4

	maxVaultFileSize = 16 << 20
	maxKeystoreSize  = 8 << 20
	maxPasswordSize  = 4 << 10
)

type Keystore struct {
	Name    string   `json:"name"`
	Bytes   []byte   `json:"bytes"`
	Aliases []string `json:"aliases"`
}

type Data struct {
	Keystores map[string]Keystore `json:"keystores"`
	NostrKey  string              `json:"nostr_key"`
}

type file struct {
	Version    int    `json:"version"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}

func New() Data { return Data{Keystores: make(map[string]Keystore)} }

// Destroy releases references to decrypted material and zeroes mutable key
// bytes. Go strings cannot be reliably wiped, so process-level dump controls
// remain part of the security boundary.
func (data *Data) Destroy() {
	for name, key := range data.Keystores {
		clear(key.Bytes)
		key.Bytes = nil
		delete(data.Keystores, name)
	}
	data.NostrKey = ""
}

func Load(path, password string) (Data, error) {
	if err := validPassword(password, false); err != nil {
		return Data{}, err
	}
	// #nosec G304 -- the operator selects the vault path; the opened descriptor
	// is required to be a bounded regular file before it is decoded.
	input, err := os.Open(path)
	if err != nil {
		return Data{}, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return Data{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxVaultFileSize {
		return Data{}, errors.New("vault must be a regular file no larger than 16 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxVaultFileSize+1))
	if err != nil {
		return Data{}, err
	}
	if len(raw) > maxVaultFileSize {
		return Data{}, errors.New("vault is too large")
	}
	var stored file
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return Data{}, fmt.Errorf("read vault: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return Data{}, fmt.Errorf("read vault: %w", err)
	}
	if stored.Version != 1 || len(stored.Salt) != saltSize || len(stored.Ciphertext) > maxVaultFileSize {
		return Data{}, errors.New("unsupported or corrupt vault")
	}
	plain, err := decrypt(stored.Salt, password, stored.Ciphertext)
	if err != nil {
		return Data{}, errors.New("invalid password or corrupt vault")
	}
	defer clear(plain)
	var data Data
	if err := json.Unmarshal(plain, &data); err != nil {
		return Data{}, fmt.Errorf("decode vault: %w", err)
	}
	if data.Keystores == nil {
		data.Keystores = make(map[string]Keystore)
	}
	if err := validate(data); err != nil {
		return Data{}, fmt.Errorf("decode vault: %w", err)
	}
	return data, nil
}

func Save(path, password string, data Data) error {
	if err := validPassword(password, true); err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	defer clear(plain)
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	ciphertext, err := encrypt(salt, password, plain)
	if err != nil {
		return err
	}
	stored, err := json.Marshal(file{Version: 1, Salt: salt, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return createExclusive(path, stored)
}

// Replace atomically replaces an existing vault after encrypting validated
// data. It is used for explicit identity changes such as adding a signing
// alias; new vault creation must use Save instead.
func Replace(path, password string, data Data) error {
	if err := validPassword(password, false); err != nil {
		return err
	}
	if err := validate(data); err != nil {
		return err
	}
	plain, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	defer clear(plain)
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	ciphertext, err := encrypt(salt, password, plain)
	if err != nil {
		return err
	}
	stored, err := json.Marshal(file{Version: 1, Salt: salt, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	return replace(path, stored)
}

func encrypt(salt []byte, password string, plain []byte) ([]byte, error) {
	key := derive(salt, password)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plain, nil)...), nil
}

func decrypt(salt []byte, password string, ciphertext []byte) ([]byte, error) {
	key := derive(salt, password)
	defer clear(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], nil)
}

func derive(salt []byte, password string) []byte {
	return argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, keySize)
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validPassword(password string, creating bool) error {
	if password == "" {
		return errors.New("vault password is required")
	}
	if creating && len(password) < 12 {
		return errors.New("new vault password must be at least 12 characters")
	}
	if len(password) > maxPasswordSize {
		return errors.New("vault password is too large")
	}
	return nil
}

func validate(data Data) error {
	if len(data.NostrKey) != 64 {
		return errors.New("nostr private key must be 32-byte hex")
	}
	if _, err := hex.DecodeString(data.NostrKey); err != nil {
		return errors.New("nostr private key must be 32-byte hex")
	}
	if _, err := nostr.GetPublicKey(data.NostrKey); err != nil {
		return errors.New("invalid Nostr private key")
	}
	if len(data.Keystores) == 0 || len(data.Keystores) > 8 {
		return errors.New("vault must contain between one and eight keystores")
	}
	for name, key := range data.Keystores {
		if strings.TrimSpace(name) == "" || len(name) > 255 || key.Name != name {
			return errors.New("invalid keystore name")
		}
		if len(key.Bytes) == 0 || len(key.Bytes) > maxKeystoreSize {
			return errors.New("invalid keystore size")
		}
		if len(key.Aliases) == 0 || len(key.Aliases) > 64 {
			return errors.New("keystore must contain between one and 64 aliases")
		}
		seen := make(map[string]struct{}, len(key.Aliases))
		for _, alias := range key.Aliases {
			if strings.TrimSpace(alias) == "" || len(alias) > 255 {
				return errors.New("invalid key alias")
			}
			if _, ok := seen[alias]; ok {
				return errors.New("duplicate key alias")
			}
			seen[alias] = struct{}{}
		}
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON")
		}
		return err
	}
	return nil
}

func createExclusive(path string, contents []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hotbox-vault-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return errors.New("refusing to overwrite existing vault")
		}
		return err
	}
	return nil
}

func replace(path string, contents []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hotbox-vault-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
