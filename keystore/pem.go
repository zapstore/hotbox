package keystore

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

func parsePEM(data []byte) ([]Entry, error) {
	var pkcs8 []byte
	var certs [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			pkcs8 = append([]byte(nil), block.Bytes...)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("keystore private key is invalid")
			}
			pkcs8, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, err
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("keystore private key is invalid")
			}
			pkcs8, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, err
			}
		case "CERTIFICATE":
			certs = append(certs, append([]byte(nil), block.Bytes...))
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted PEM is not supported; export a PKCS#12 file")
		default:
			if strings.Contains(block.Type, "PRIVATE KEY") {
				return nil, errors.New("encrypted PEM is not supported; export a PKCS#12 file")
			}
		}
	}
	if pkcs8 == nil {
		return nil, errors.New("keystore has no private key")
	}
	ordered, err := orderCerts(pkcs8, certs)
	if err != nil {
		wipe(pkcs8)
		return nil, err
	}
	alias := aliasFromCert(ordered[0])
	entry, err := finish(alias, pkcs8, ordered)
	if err != nil {
		wipe(pkcs8)
		return nil, err
	}
	return []Entry{entry}, nil
}

func aliasFromCert(der []byte) string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "key"
	}
	alias := strings.TrimSpace(cert.Subject.CommonName)
	if validAlias(alias) != nil {
		return "key"
	}
	return alias
}
