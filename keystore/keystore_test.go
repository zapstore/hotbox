package keystore_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/zapstore/hotbox/keystore"
)

func TestPEMAndPKCS12(t *testing.T) {
	key, cert := testKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}); err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		t.Fatal(err)
	}
	entries, err := keystore.Parse(buf.Bytes(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Alias != "zapstore" || !bytes.Equal(entries[0].Certs[0], cert) {
		t.Fatalf("pem entry %+v", entries[0].Alias)
	}
	wipe(entries[0].PKCS8)
}

func TestKeytoolPKCS12(t *testing.T) {
	if _, err := exec.LookPath("keytool"); err != nil {
		t.Skip("keytool not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "release.p12")
	cmd := exec.Command("keytool", "-genkeypair", "-alias", "release", "-keyalg", "EC", "-groupname", "secp256r1",
		"-keystore", path, "-storetype", "PKCS12", "-storepass", "storepass",
		"-dname", "CN=zapstore", "-validity", "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keytool: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Parse(data, "wrong", ""); !errors.Is(err, keystore.ErrPassword) {
		t.Fatalf("pkcs12 password: %v", err)
	}
	entries, err := keystore.Parse(data, "storepass", "")
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Alias != "release" || len(entries[0].Certs) != 1 {
		t.Fatalf("alias %q certs %d", entries[0].Alias, len(entries[0].Certs))
	}
	wipe(entries[0].PKCS8)
}

func TestKeytoolJKS(t *testing.T) {
	if _, err := exec.LookPath("keytool"); err != nil {
		t.Skip("keytool not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "release.jks")
	cmd := exec.Command("keytool", "-genkeypair", "-alias", "Release", "-keyalg", "RSA", "-keysize", "2048",
		"-keystore", path, "-storetype", "JKS", "-storepass", "storepass", "-keypass", "keypass",
		"-dname", "CN=zapstore", "-validity", "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keytool: %v\n%s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Parse(data, "wrong", ""); !errors.Is(err, keystore.ErrPassword) {
		t.Fatalf("store password: %v", err)
	}
	if _, err := keystore.Parse(data, "storepass", ""); !errors.Is(err, keystore.ErrKeyPassword) {
		t.Fatalf("key password: %v", err)
	}
	entries, err := keystore.Parse(data, "storepass", "keypass")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Alias != "release" || len(entries[0].Certs) != 1 {
		t.Fatalf("alias %q certs %d", entries[0].Alias, len(entries[0].Certs))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(entries[0].PKCS8)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Fatalf("key type %T", parsed)
	}
	wipe(entries[0].PKCS8)
}

func testKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
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

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
