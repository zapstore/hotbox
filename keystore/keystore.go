// Package keystore reads one Android signing key from a JKS, PKCS#12, or PEM
// file. The caller seals the result into a new vault and wipes it.
package keystore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

const maxKeystore = 1 << 20

// ErrPassword means the store password did not open the file.
// ErrKeyPassword means the file opened and the key password was rejected.
var (
	ErrPassword    = errors.New("keystore password was rejected")
	ErrKeyPassword = errors.New("key password was rejected")
)

// Entry is one private key and its certificate chain, leaf first.
// PKCS8 is PrivateKeyInfo DER. The caller wipes it.
type Entry struct {
	Alias string
	PKCS8 []byte
	Certs [][]byte
}

// Parse reads data. An empty keyPassword uses storePassword for the key.
// PKCS#12 uses storePassword for the whole file. PEM uses keyPassword only
// when the private key is encrypted, which this package rejects.
func Parse(data []byte, storePassword, keyPassword string) ([]Entry, error) {
	if len(data) == 0 || len(data) > maxKeystore {
		return nil, errors.New("keystore is empty or too large")
	}
	if keyPassword == "" {
		keyPassword = storePassword
	}
	switch {
	case bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfe, 0xed}):
		return parseJKS(data, storePassword, keyPassword)
	case bytes.HasPrefix(data, []byte("-----BEGIN ")):
		return parsePEM(data)
	default:
		return parsePKCS12(data, storePassword)
	}
}

func finish(alias string, pkcs8 []byte, certs [][]byte) (Entry, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return Entry{}, errors.New("keystore private key is not PKCS#8")
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return Entry{}, errors.New("keystore key must be RSA or EC")
		}
	}
	if len(certs) == 0 {
		return Entry{}, errors.New("keystore entry has no certificate")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return Entry{}, errors.New("keystore certificate is invalid")
	}
	if !samePublic(key, leaf.PublicKey) {
		return Entry{}, errors.New("keystore certificate does not match the key")
	}
	for _, der := range certs[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return Entry{}, errors.New("keystore certificate is invalid")
		}
	}
	if err := validAlias(alias); err != nil {
		return Entry{}, err
	}
	keyCopy := append([]byte(nil), pkcs8...)
	chain := make([][]byte, len(certs))
	for i, der := range certs {
		chain[i] = append([]byte(nil), der...)
	}
	return Entry{Alias: alias, PKCS8: keyCopy, Certs: chain}, nil
}

func validAlias(alias string) error {
	if alias == "" || len(alias) > 128 || strings.ContainsAny(alias, "'\"\r\n\\") {
		return fmt.Errorf("keystore alias %q is invalid", alias)
	}
	return nil
}

func samePublic(key crypto.PrivateKey, pub crypto.PublicKey) bool {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		other, ok := pub.(*rsa.PublicKey)
		return ok && k.PublicKey.Equal(other)
	case *ecdsa.PrivateKey:
		other, ok := pub.(*ecdsa.PublicKey)
		return ok && k.PublicKey.Equal(other)
	default:
		return false
	}
}

// Order puts the certificate that matches pkcs8 first and then any issuer.
func orderCerts(pkcs8 []byte, ders [][]byte) ([][]byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	leaf := -1
	for i, c := range certs {
		if samePublic(key, c.PublicKey) {
			leaf = i
			break
		}
	}
	if leaf < 0 {
		return nil, errors.New("keystore certificate does not match the key")
	}
	out := [][]byte{certs[leaf].Raw}
	cur := certs[leaf]
	used := map[int]bool{leaf: true}
	for {
		if bytes.Equal(cur.RawSubject, cur.RawIssuer) {
			break
		}
		next := -1
		for i, c := range certs {
			if used[i] {
				continue
			}
			if bytes.Equal(c.RawSubject, cur.RawIssuer) {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		out = append(out, certs[next].Raw)
		used[next] = true
		cur = certs[next]
	}
	return out, nil
}
