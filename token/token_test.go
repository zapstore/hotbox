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
	"math/big"
	"net"
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
	tok, err := Start(ctx, Key{
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
