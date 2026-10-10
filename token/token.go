// Package token serves one Android signing key on a same-user Unix socket.
// The private key is not stored. Each signature calls Use and drops the bytes.
package token

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Key is the unlocked signing material. Use decrypts the PKCS#8 key for the
// callback. PIN is 32 hex characters. Certs is leaf first.
type Key struct {
	Alias string
	PIN   [32]byte
	Certs [][]byte
	Use   func(context.Context, func([]byte) error) error
}

// Token is one listening signer. Path, Config, Alias, and Pin are printed
// for apksigner. Pin is empty when the token is closed.
type Token struct {
	Alias  string
	Path   string
	Config string

	pin   [32]byte
	certs []certInfo
	use   func(context.Context, func([]byte) error) error
	log   *slog.Logger
	ctx   context.Context

	ln   net.Listener
	sem  chan struct{}
	once sync.Once
	done chan struct{}
}

type certInfo struct {
	der     []byte
	subject []byte
	issuer  []byte
	serial  []byte
}

// Start listens on a socket under /tmp/hotbox-<uid>. lib is the PKCS#11
// module path. An empty lib still serves the socket and leaves Config empty.
func Start(ctx context.Context, key Key, lib string, log *slog.Logger) (*Token, error) {
	if key.Use == nil {
		return nil, errors.New("android signer is missing")
	}
	if len(key.Certs) == 0 {
		return nil, errors.New("android certificate is missing")
	}
	leaf, err := x509.ParseCertificate(key.Certs[0])
	if err != nil {
		return nil, errors.New("android certificate is invalid")
	}
	if _, _, _, err := publicFields(leaf); err != nil {
		return nil, err
	}
	certs := make([]certInfo, len(key.Certs))
	for i, der := range key.Certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.New("android certificate is invalid")
		}
		certs[i] = certInfo{
			der:     append([]byte(nil), der...),
			subject: append([]byte(nil), c.RawSubject...),
			issuer:  append([]byte(nil), c.RawIssuer...),
			serial:  c.SerialNumber.Bytes(),
		}
	}
	dir, err := socketDir()
	if err != nil {
		return nil, err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	name := hex.EncodeToString(id[:])
	path := filepath.Join(dir, name+".sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, err
	}
	cfg := ""
	if lib != "" {
		cfg = filepath.Join(dir, name+".pkcs11.cfg")
		text := "name = Hotbox\nlibrary = " + lib + "\nslotListIndex = 0\n"
		if err := os.WriteFile(cfg, []byte(text), 0600); err != nil {
			_ = ln.Close()
			_ = os.Remove(path)
			return nil, err
		}
	}
	t := &Token{
		Alias:  key.Alias,
		Path:   path,
		Config: cfg,
		pin:    key.PIN,
		certs:  certs,
		use:    key.Use,
		log:    log,
		ctx:    ctx,
		ln:     ln,
		sem:    make(chan struct{}, 4),
		done:   make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			t.Close()
		case <-t.done:
		}
	}()
	go t.accept()
	return t, nil
}

// Pin is the PKCS#11 login PIN. It is empty after Close.
func (t *Token) Pin() string {
	if t == nil {
		return ""
	}
	if t.pin == [32]byte{} {
		return ""
	}
	return string(t.pin[:])
}

// Close stops the listener and removes the socket. It does not wait for an
// in-flight signature to finish before returning, but Use holds the vault
// until that signature returns.
func (t *Token) Close() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		close(t.done)
		_ = t.ln.Close()
		_ = os.Remove(t.Path)
		if t.Config != "" {
			_ = os.Remove(t.Config)
		}
		t.pin = [32]byte{}
		runtime.KeepAlive(t)
	})
}

func (t *Token) accept() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.sem <- struct{}{}:
			go func() {
				defer func() { <-t.sem }()
				t.handle(conn)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func (t *Token) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := sameUser(conn); err != nil {
		t.warn("android connection", "err", err.Error())
		return
	}
	op, body, err := readFrame(conn)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.warn("android connection", "err", err.Error())
		}
		return
	}
	switch op {
	case opInfo:
		t.serveInfo(conn, body)
	case opSign:
		t.serveSign(conn, body)
	default:
		_ = writeFrame(conn, statusBad, nil)
	}
}

func (t *Token) serveInfo(conn net.Conn, body []byte) {
	pin, rest, err := takePin(body)
	if err != nil || len(rest) != 0 || !t.pinOK(pin) {
		t.warn("android token", "result", "denied")
		_ = writeFrame(conn, statusPIN, nil)
		return
	}
	payload, err := t.infoBody()
	if err != nil {
		t.warn("android token", "result", "failed", "err", err.Error())
		_ = writeFrame(conn, statusFailed, nil)
		return
	}
	_ = writeFrame(conn, statusOK, payload)
}

func (t *Token) serveSign(conn net.Conn, body []byte) {
	pin, rest, err := takePin(body)
	if err != nil || !t.pinOK(pin) {
		t.warn("android signature", "alias", t.Alias, "result", "denied")
		_ = writeFrame(conn, statusPIN, nil)
		return
	}
	if len(rest) < 8 {
		_ = writeFrame(conn, statusBad, nil)
		return
	}
	mech := binary.BigEndian.Uint32(rest[:4])
	n := binary.BigEndian.Uint32(rest[4:8])
	data := rest[8:]
	if uint32(len(data)) != n {
		_ = writeFrame(conn, statusBad, nil)
		return
	}
	var sig []byte
	err = t.use(t.ctx, func(pkcs8 []byte) error {
		// Use may hand back the vault's own buffer. Copy it, and wipe only the copy.
		key := append([]byte(nil), pkcs8...)
		defer wipe(key)
		var signErr error
		sig, signErr = signPKCS8(key, mech, data)
		return signErr
	})
	if err != nil {
		status := byte(statusFailed)
		if errors.Is(err, errMechanism) {
			status = statusMechanism
		}
		t.warn("android signature", "alias", t.Alias, "mechanism", mechanismName(mech), "result", "rejected", "err", err.Error())
		_ = writeFrame(conn, status, nil)
		return
	}
	out := make([]byte, 4+len(sig))
	binary.BigEndian.PutUint32(out[:4], uint32(len(sig)))
	copy(out[4:], sig)
	t.info("android signature", "alias", t.Alias, "mechanism", mechanismName(mech), "bytes", len(data))
	_ = writeFrame(conn, statusOK, out)
}

func (t *Token) infoBody() ([]byte, error) {
	leaf, err := x509.ParseCertificate(t.certs[0].der)
	if err != nil {
		return nil, err
	}
	kind, a, b, err := publicFields(leaf)
	if err != nil {
		return nil, err
	}
	if len(t.Alias) > 0xffff || len(a) > 0xffff || len(b) > 0xffff || len(t.certs) > 255 {
		return nil, errors.New("android certificate is too large")
	}
	buf := make([]byte, 0, 256)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(t.Alias)))
	buf = append(buf, u16[:]...)
	buf = append(buf, t.Alias...)
	buf = append(buf, kind)
	binary.BigEndian.PutUint16(u16[:], uint16(len(a)))
	buf = append(buf, u16[:]...)
	buf = append(buf, a...)
	binary.BigEndian.PutUint16(u16[:], uint16(len(b)))
	buf = append(buf, u16[:]...)
	buf = append(buf, b...)
	buf = append(buf, byte(len(t.certs)))
	var u32 [4]byte
	for _, c := range t.certs {
		if len(c.subject) > 0xffff || len(c.issuer) > 0xffff || len(c.serial) > 0xffff {
			return nil, errors.New("android certificate is too large")
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(c.der)))
		buf = append(buf, u32[:]...)
		buf = append(buf, c.der...)
		binary.BigEndian.PutUint16(u16[:], uint16(len(c.subject)))
		buf = append(buf, u16[:]...)
		buf = append(buf, c.subject...)
		binary.BigEndian.PutUint16(u16[:], uint16(len(c.issuer)))
		buf = append(buf, u16[:]...)
		buf = append(buf, c.issuer...)
		binary.BigEndian.PutUint16(u16[:], uint16(len(c.serial)))
		buf = append(buf, u16[:]...)
		buf = append(buf, c.serial...)
	}
	return buf, nil
}

func (t *Token) pinOK(pin string) bool {
	if len(pin) != len(t.pin) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pin), t.pin[:]) == 1
}

func (t *Token) info(msg string, args ...any) {
	if t != nil && t.log != nil {
		t.log.Info(msg, args...)
	}
}

func (t *Token) warn(msg string, args ...any) {
	if t != nil && t.log != nil {
		t.log.Warn(msg, args...)
	}
}

func socketDir() (string, error) {
	dir := fmt.Sprintf("/tmp/hotbox-%d", os.Getuid())
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0700); err != nil {
			return "", err
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return "", fmt.Errorf("signer directory %s is not a private directory", dir)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return "", fmt.Errorf("signer directory %s is owned by another user", dir)
	}
	if fi.Mode().Perm() != 0700 {
		if err := os.Chmod(dir, 0700); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// LibraryPath is the PKCS#11 module next to this executable, when it exists.
func LibraryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	ext := "so"
	if runtime.GOOS == "darwin" {
		ext = "dylib"
	}
	path := filepath.Join(filepath.Dir(exe), fmt.Sprintf("libhotbox-pkcs11-%s-%s.%s", runtime.GOOS, runtime.GOARCH, ext))
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}
