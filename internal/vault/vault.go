// Package vault seals one Nostr secret key with a password.
package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	nostr "github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	version   = 1
	saltSize  = 16
	keySize   = chacha20poly1305.KeySize
	timeCost  = 3
	memoryKiB = 64 * 1024
	threads   = 4

	maxFileSize     = 1 << 20
	maxPasswordSize = 4 << 10
)

var aad = []byte("hotbox-identity-v1")

type file struct {
	Version int    `json:"version"`
	KDF     kdf    `json:"kdf"`
	Wrap    []byte `json:"wrap"`
	Data    []byte `json:"data"`
}

type kdf struct {
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

const stateSize = 1 + 32 + 32 + 16 + 2 + 2

// State is the sealed bunker identity. Ports, path token, and connect secret
// are fixed at creation so the bunker URL does not change between runs.
type State struct {
	Secret  [32]byte
	Connect [32]byte
	Token   [16]byte
	WSPort  uint16
	WSSPort uint16
}

func (s *State) Wipe() { *s = State{} }

// Create seals state into a new mode-0600 file. It refuses to replace an existing file.
func Create(path, password string, state State) error {
	if err := validPassword(password, true); err != nil {
		return err
	}
	if err := state.valid(); err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	dek := make([]byte, keySize)
	if _, err := rand.Read(dek); err != nil {
		clear(dek)
		return fmt.Errorf("generate data key: %w", err)
	}
	defer clear(dek)
	kek := derive(salt, password)
	defer clear(kek)
	wrap, err := seal(kek, dek, wrapAAD(salt))
	if err != nil {
		return err
	}
	plain := state.marshal()
	defer clear(plain)
	data, err := seal(dek, plain, aad)
	if err != nil {
		return err
	}
	stored, err := json.Marshal(file{
		Version: version,
		KDF:     kdf{Salt: salt, Time: timeCost, Memory: memoryKiB, Threads: threads},
		Wrap:    wrap,
		Data:    data,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return createExclusive(path, stored)
}

// Open decrypts a vault. The caller must Wipe the returned state.
// A wrong password and a damaged file return the same error.
func Open(path, password string) (State, error) {
	var state State
	if err := validPassword(password, false); err != nil {
		return state, err
	}
	raw, err := readRegular(path)
	if err != nil {
		return state, err
	}
	var stored file
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil || requireEOF(decoder) != nil {
		return state, errors.New("unsupported or corrupt vault")
	}
	if stored.Version != version || !acceptable(stored.KDF) {
		return state, errors.New("unsupported or corrupt vault")
	}
	kek := derive(stored.KDF.Salt, password)
	defer clear(kek)
	dek, err := open(kek, stored.Wrap, wrapAAD(stored.KDF.Salt))
	if err != nil || len(dek) != keySize {
		clear(dek)
		return state, errors.New("invalid password or corrupt vault")
	}
	defer clear(dek)
	plain, err := open(dek, stored.Data, aad)
	if err != nil {
		clear(plain)
		return state, errors.New("invalid password or corrupt vault")
	}
	defer clear(plain)
	state, err = unmarshalState(plain)
	if err != nil {
		return State{}, errors.New("invalid password or corrupt vault")
	}
	return state, nil
}

func (s State) valid() error {
	if _, err := nostr.GetPublicKey(hex.EncodeToString(s.Secret[:])); err != nil {
		return errors.New("invalid Nostr private key")
	}
	if s.Connect == [32]byte{} || s.Token == [16]byte{} {
		return errors.New("bunker secret is missing")
	}
	if s.WSPort == 0 || s.WSSPort == 0 || s.WSPort == s.WSSPort {
		return errors.New("bunker ports are invalid")
	}
	return nil
}

func (s State) marshal() []byte {
	buf := make([]byte, stateSize)
	buf[0] = 1
	copy(buf[1:33], s.Secret[:])
	copy(buf[33:65], s.Connect[:])
	copy(buf[65:81], s.Token[:])
	binary.BigEndian.PutUint16(buf[81:83], s.WSPort)
	binary.BigEndian.PutUint16(buf[83:85], s.WSSPort)
	return buf
}

func unmarshalState(plain []byte) (State, error) {
	var state State
	if len(plain) != stateSize || plain[0] != 1 {
		return state, errors.New("unsupported vault state")
	}
	copy(state.Secret[:], plain[1:33])
	copy(state.Connect[:], plain[33:65])
	copy(state.Token[:], plain[65:81])
	state.WSPort = binary.BigEndian.Uint16(plain[81:83])
	state.WSSPort = binary.BigEndian.Uint16(plain[83:85])
	if err := state.valid(); err != nil {
		return State{}, err
	}
	return state, nil
}

func acceptable(k kdf) bool {
	return len(k.Salt) == saltSize && k.Time == timeCost && k.Memory == memoryKiB && k.Threads == threads
}

func wrapAAD(salt []byte) []byte {
	var params [9]byte
	binary.BigEndian.PutUint32(params[0:4], timeCost)
	binary.BigEndian.PutUint32(params[4:8], memoryKiB)
	params[8] = threads
	out := make([]byte, 0, len(aad)+len(params)+len(salt))
	out = append(out, aad...)
	out = append(out, params[:]...)
	return append(out, salt...)
}

func derive(salt []byte, password string) []byte {
	return argon2.IDKey([]byte(password), salt, timeCost, memoryKiB, threads, keySize)
}

func seal(key, plain, extra []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plain, extra)...), nil
}

func open(key, ciphertext, extra []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():], extra)
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

func readRegular(path string) ([]byte, error) {
	input, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil, errors.New("vault must be a regular file no larger than 1 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxFileSize {
		return nil, errors.New("vault is too large")
	}
	return raw, nil
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
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hotbox-vault-*")
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

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
