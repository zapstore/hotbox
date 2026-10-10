package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestApksigner(t *testing.T) {
	apksigner := os.Getenv("APKSIGNER")
	if apksigner == "" {
		apksigner = "/opt/homebrew/share/android-commandlinetools/build-tools/35.0.0/apksigner"
	}
	if _, err := os.Stat(apksigner); err != nil {
		if found, lookErr := exec.LookPath("apksigner"); lookErr == nil {
			apksigner = found
		} else {
			t.Skip("apksigner not installed")
		}
	}
	lib := buildModule(t)
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	apk := filepath.Join(filepath.Dir(file), "..", "testdata", "hotbox-unsigned.apk")
	if _, err := os.Stat(apk); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "zapstore"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	copy(pin[:], []byte("abcdef0123456789abcdef0123456789"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tok, err := Start(ctx, t.Name(), Key{
		Alias: "zapstore",
		PIN:   pin,
		Certs: [][]byte{der},
		Use: func(_ context.Context, fn func([]byte) error) error {
			return fn(pkcs8)
		},
	}, lib, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	if tok.Config == "" {
		t.Fatal("missing pkcs11 config")
	}

	out := filepath.Join(t.TempDir(), "signed.apk")
	cmd := exec.Command(apksigner, "sign",
		"--provider-class", "sun.security.pkcs11.SunPKCS11",
		"--provider-arg", tok.Config,
		"--ks", "NONE",
		"--ks-type", "PKCS11",
		"--ks-key-alias", tok.Alias,
		"--ks-pass", "env:HOTBOX_PIN",
		"--in", apk,
		"--out", out,
	)
	cmd.Env = append(os.Environ(),
		"HOTBOX_TOKEN="+tok.Path,
		"HOTBOX_PIN="+tok.Pin(),
		"JAVA_TOOL_OPTIONS=--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("apksigner sign: %v\n%s", err, output)
	}
	verify := exec.Command(apksigner, "verify", "--verbose", out)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("apksigner verify: %v\n%s", err, output)
	}
}

func buildModule(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not installed")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	src := filepath.Join(filepath.Dir(file), "..", "pkcs11", "hotbox.c")
	out := filepath.Join(t.TempDir(), "libhotbox-pkcs11.dylib")
	flags := []string{"-dynamiclib", "-O2", "-Wall", "-Wextra", "-Wno-cast-function-type-mismatch", "-o", out, src}
	if runtime.GOOS != "darwin" {
		out = filepath.Join(t.TempDir(), "libhotbox-pkcs11.so")
		flags = []string{"-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Wno-cast-function-type-mismatch", "-o", out, src}
	}
	cmd := exec.Command(cc, flags...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile pkcs11: %v\n%s", err, output)
	}
	return out
}
