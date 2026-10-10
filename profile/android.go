package profile

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	androidVersion = 1
	maxCerts       = 8
	maxCertDER     = 16 << 10
	maxAndroidMeta = 256 << 10
)

// AndroidKey is the signing material sealed at vault creation.
// PIN is 32 hex characters. PKCS8 is PrivateKeyInfo DER. Certs is leaf first.
// The caller wipes PKCS8.
type AndroidKey struct {
	Alias string
	PIN   [32]byte
	PKCS8 []byte
	Certs [][]byte
}

// Android is the public half of the signing key plus a callback for the private half.
// Use decrypts the PKCS#8 key for the callback. Wipe clears PIN.
type Android struct {
	Alias string
	PIN   [32]byte
	Certs [][]byte
	Use   func(context.Context, func([]byte) error) error
}

func (a *Android) Wipe() {
	if a == nil {
		return
	}
	a.PIN = [32]byte{}
}

func validAndroid(a AndroidKey) error {
	if err := validAlias(a.Alias); err != nil {
		return err
	}
	for _, c := range a.PIN {
		if !isHex(c) {
			return errors.New("android pin is invalid")
		}
	}
	if len(a.Certs) == 0 || len(a.Certs) > maxCerts {
		return errors.New("android certificate chain is invalid")
	}
	key, err := x509.ParsePKCS8PrivateKey(a.PKCS8)
	if err != nil {
		return errors.New("android private key is invalid")
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return errors.New("android private key must be RSA or EC")
	}
	leaf, err := x509.ParseCertificate(a.Certs[0])
	if err != nil {
		return errors.New("android certificate is invalid")
	}
	if !pubEqual(key, leaf.PublicKey) {
		return errors.New("android certificate does not match the key")
	}
	for _, der := range a.Certs {
		if len(der) == 0 || len(der) > maxCertDER {
			return errors.New("android certificate is invalid")
		}
		if _, err := x509.ParseCertificate(der); err != nil {
			return errors.New("android certificate is invalid")
		}
	}
	return nil
}

func pubEqual(key any, pub any) bool {
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

func validAlias(alias string) error {
	if alias == "" || len(alias) > 128 || strings.ContainsAny(alias, "'\"\r\n\\") {
		return fmt.Errorf("android alias %q is invalid", alias)
	}
	return nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

func encodeAndroid(a AndroidKey) ([]byte, error) {
	n := 1 + 32 + 2 + len(a.Alias) + 1
	for _, der := range a.Certs {
		n += 4 + len(der)
	}
	if n > maxAndroidMeta {
		return nil, errors.New("android certificate chain is too large")
	}
	buf := make([]byte, 0, n)
	buf = append(buf, androidVersion)
	buf = append(buf, a.PIN[:]...)
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(a.Alias)))
	buf = append(buf, ln[:]...)
	buf = append(buf, a.Alias...)
	buf = append(buf, byte(len(a.Certs)))
	var cl [4]byte
	for _, der := range a.Certs {
		binary.BigEndian.PutUint32(cl[:], uint32(len(der)))
		buf = append(buf, cl[:]...)
		buf = append(buf, der...)
	}
	return buf, nil
}

func decodeAndroid(buf []byte) (alias string, pin [32]byte, certs [][]byte, err error) {
	if len(buf) < 1+32+2+1 || buf[0] != androidVersion || len(buf) > maxAndroidMeta {
		err = errCorrupt
		return
	}
	copy(pin[:], buf[1:33])
	for _, c := range pin {
		if !isHex(c) {
			err = errCorrupt
			return
		}
	}
	aliasLen := int(binary.BigEndian.Uint16(buf[33:35]))
	buf = buf[35:]
	if aliasLen > len(buf) {
		err = errCorrupt
		return
	}
	alias = string(buf[:aliasLen])
	buf = buf[aliasLen:]
	if err = validAlias(alias); err != nil {
		err = errCorrupt
		return
	}
	if len(buf) < 1 {
		err = errCorrupt
		return
	}
	n := int(buf[0])
	buf = buf[1:]
	if n == 0 || n > maxCerts {
		err = errCorrupt
		return
	}
	certs = make([][]byte, 0, n)
	for range n {
		if len(buf) < 4 {
			err = errCorrupt
			return
		}
		cl := int(binary.BigEndian.Uint32(buf[:4]))
		buf = buf[4:]
		if cl == 0 || cl > maxCertDER || cl > len(buf) {
			err = errCorrupt
			return
		}
		der := append([]byte(nil), buf[:cl]...)
		if _, parseErr := x509.ParseCertificate(der); parseErr != nil {
			err = errCorrupt
			return
		}
		certs = append(certs, der)
		buf = buf[cl:]
	}
	if len(buf) != 0 {
		err = errCorrupt
	}
	return
}

func androidPath(name string) string    { return "profiles/" + name + "/android" }
func androidKeyPath(name string) string { return "profiles/" + name + "/android-key" }
