package token

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSignOverSocket(t *testing.T) {
	key, der := testCert(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	copy(pin[:], []byte("0123456789abcdef0123456789abcdef"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tok, err := Start(ctx, t.Name(), Key{
		Alias: "zapstore",
		PIN:   pin,
		Certs: [][]byte{der},
		Use: func(_ context.Context, fn func([]byte) error) error {
			return fn(pkcs8)
		},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	conn := dial(t, tok.Path)
	body, _ := pinBody("00000000000000000000000000000000")
	if err := writeFrame(conn, opInfo, body); err != nil {
		t.Fatal(err)
	}
	status, _, err := readFrame(conn)
	if err != nil || status != statusPIN {
		t.Fatalf("info status %d err %v", status, err)
	}
	_ = conn.Close()

	conn = dial(t, tok.Path)
	body, _ = pinBody(string(pin[:]))
	if err := writeFrame(conn, opInfo, body); err != nil {
		t.Fatal(err)
	}
	status, info, err := readFrame(conn)
	if err != nil || status != statusOK || !bytes.Contains(info, []byte("zapstore")) {
		t.Fatalf("info status %d err %v", status, err)
	}
	_ = conn.Close()

	conn = dial(t, tok.Path)
	msg := []byte("apk-digest")
	req := append(body, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(req[len(body):], ckmECDSASHA256)
	var nbuf [4]byte
	binary.BigEndian.PutUint32(nbuf[:], uint32(len(msg)))
	req = append(req, nbuf[:]...)
	req = append(req, msg...)
	if err := writeFrame(conn, opSign, req); err != nil {
		t.Fatal(err)
	}
	status, signed, err := readFrame(conn)
	if err != nil || status != statusOK || len(signed) < 4 {
		t.Fatalf("sign status %d len %d err %v", status, len(signed), err)
	}
	sigLen := binary.BigEndian.Uint32(signed[:4])
	sig := signed[4:]
	if uint32(len(sig)) != sigLen || len(sig) != 64 {
		t.Fatalf("sig len %d field %d", len(sig), sigLen)
	}
	sum := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, sum[:], r, s) {
		t.Fatal("signature did not verify")
	}
}

func TestPaths(t *testing.T) {
	sock, cfg, err := Paths("zapstore")
	if err != nil {
		t.Fatal(err)
	}
	again, againCfg, err := Paths("zapstore")
	if err != nil || sock != again || cfg != againCfg {
		t.Fatalf("paths changed: %s %s", sock, cfg)
	}
	if !strings.HasPrefix(sock, "/tmp/hotbox-") || !strings.HasSuffix(sock, "/zapstore.sock") || cfg != strings.TrimSuffix(sock, ".sock")+".pkcs11.cfg" {
		t.Fatalf("socket %s config %s", sock, cfg)
	}
	if _, _, err := Paths(""); err == nil {
		t.Fatal("accepted an empty name")
	}
	if _, _, err := Paths("../zapstore"); err == nil {
		t.Fatal("accepted a parent path")
	}
}

func TestSignerRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := startSigner(t, ctx, t.Name())
	if _, err := startSignerErr(t, ctx, t.Name()); err == nil {
		t.Fatal("second signer started")
	}
	first.Close()
	if err := os.WriteFile(first.Path, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	second := startSigner(t, ctx, t.Name())
	second.Close()
	sock, _, err := Paths(t.Name())
	if err != nil || first.Path != sock || second.Path != sock {
		t.Fatalf("path %s then %s", first.Path, second.Path)
	}
}

func startSigner(t *testing.T, ctx context.Context, name string) *Token {
	t.Helper()
	tok, err := startSignerErr(t, ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func startSignerErr(t *testing.T, ctx context.Context, name string) (*Token, error) {
	t.Helper()
	key, der := testCert(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var pin [32]byte
	copy(pin[:], []byte("0123456789abcdef0123456789abcdef"))
	return Start(ctx, name, Key{
		Alias: "hotbox",
		PIN:   pin,
		Certs: [][]byte{der},
		Use: func(_ context.Context, fn func([]byte) error) error {
			return fn(pkcs8)
		},
	}, "", nil)
}

func testCert(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zapstore"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

func TestLibraryBesideFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "dist", "hotbox")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	ext := "so"
	if runtime.GOOS == "darwin" {
		ext = "dylib"
	}
	lib := filepath.Join(dir, "dist", fmt.Sprintf("libhotbox-pkcs11-%s-%s.%s", runtime.GOOS, runtime.GOARCH, ext))
	if err := os.WriteFile(lib, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bin", "hotbox")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(lib)
	if err != nil {
		t.Fatal(err)
	}
	if got := libraryBeside(link); got != want {
		t.Fatalf("libraryBeside(symlink) = %q, want %q", got, want)
	}
	if got := libraryBeside(bin); got != want {
		t.Fatalf("libraryBeside(binary) = %q, want %q", got, want)
	}
}

func dial(t *testing.T, path string) net.Conn {
	t.Helper()
	var last error
	for range 20 {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return conn
		}
		last = err
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(last)
	return nil
}
