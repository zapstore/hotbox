package profile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vaultcore/vault"
)

func TestOpenRefusesMissingContent(t *testing.T) {
	ctx := t.Context()
	path, keys := dirProfile(t)
	pass := []byte("correct horse battery")
	v, prof, err := Open(ctx, path, keys, pass)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Name != "zapstore" || prof.Android.Use == nil {
		t.Fatal("directory profile did not load")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := vaultcore.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}

	blobs := blobFiles(t, path)
	if len(blobs) != 4 {
		t.Fatalf("%d blobs, want 4", len(blobs))
	}
	named := map[string]string{}
	for _, blob := range blobs {
		aside := blob + ".aside"
		if err := os.Rename(blob, aside); err != nil {
			t.Fatal(err)
		}
		_, _, openErr := Open(ctx, path, keys, pass)
		if renameErr := os.Rename(aside, blob); renameErr != nil {
			t.Fatal(renameErr)
		}
		if !errors.Is(openErr, vaultcore.ErrMissing) {
			t.Fatalf("open with %s removed: %v", filepath.Base(blob), openErr)
		}
		for _, p := range []string{nsecPath("zapstore"), androidKeyPath("zapstore")} {
			if strings.Contains(openErr.Error(), p) {
				named[p] = blob
			}
		}
	}
	if named[nsecPath("zapstore")] == "" {
		t.Fatal("no removed blob named the nsec")
	}
	hit := named[androidKeyPath("zapstore")]
	if hit == "" {
		t.Fatal("no removed blob named the android key")
	}

	if err := os.Rename(hit, hit+".aside"); err != nil {
		t.Fatal(err)
	}
	_, _, err = Open(ctx, path, keys, pass)
	if !errors.Is(err, vaultcore.ErrMissing) || !strings.Contains(err.Error(), androidKeyPath("zapstore")) {
		t.Fatalf("second open: %v", err)
	}
	after, err := vaultcore.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Entries != before.Entries {
		t.Fatalf("entries %d, want %d", after.Entries, before.Entries)
	}
}

func dirProfile(t *testing.T) (string, string) {
	t.Helper()
	ctx := t.Context()
	dir := t.TempDir()
	path := filepath.Join(dir, "zapstore.hotbox")
	keys := filepath.Join(dir, "zapstore.key")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer wipe(secret)
	if err := validSecret(secret); err != nil {
		t.Fatal(err)
	}
	android := androidKeyForTest(t)
	defer wipe(android.PKCS8)
	var connect [32]byte
	var token [16]byte
	connect[0] = 7
	token[0] = 9
	v, err := vaultcore.Create(ctx, path, keys, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Add(ctx, nsecPath("zapstore"), bytes.NewReader(secret), true); err != nil {
		t.Fatal(err)
	}
	body := encodeBunker(connect, token, 10001, 10002)
	defer wipe(body)
	if err := v.Add(ctx, bunkerPath("zapstore"), bytes.NewReader(body), false); err != nil {
		t.Fatal(err)
	}
	meta, err := encodeAndroid(android)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(meta)
	if err := v.Add(ctx, androidPath("zapstore"), bytes.NewReader(meta), false); err != nil {
		t.Fatal(err)
	}
	if err := v.Add(ctx, androidKeyPath("zapstore"), bytes.NewReader(android.PKCS8), true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("directory vault: %v", err)
	}
	return path, keys
}

func androidKeyForTest(t *testing.T) AndroidKey {
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
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var pin [32]byte
	copy(pin[:], []byte("0123456789abcdef0123456789abcdef"))
	return AndroidKey{Alias: AndroidAlias, PIN: pin, PKCS8: pkcs8, Certs: [][]byte{der}}
}

func blobFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(root, "blobs"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
