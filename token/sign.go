package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"
)

const (
	ckmRSAPKCS          = 0x00000001
	ckmRSAPKCSPSS       = 0x0000000d
	ckmSHA256RSAPKCS    = 0x00000040
	ckmSHA384RSAPKCS    = 0x00000041
	ckmSHA512RSAPKCS    = 0x00000042
	ckmSHA256RSAPKCSPSS = 0x00000043
	ckmSHA384RSAPKCSPSS = 0x00000044
	ckmSHA512RSAPKCSPSS = 0x00000045
	ckmECDSA            = 0x00001041
	ckmECDSASHA256      = 0x00001044
	ckmECDSASHA384      = 0x00001045
	ckmECDSASHA512      = 0x00001046
)

var errMechanism = errors.New("mechanism rejected")

const (
	// proofSkew is how far a proof's created_at may be from this clock.
	proofSkew = 5 * time.Minute
	// proofMaxLife bounds a proof's validity. It matches the zsp default plus a day.
	proofMaxLife = (2*365 + 1) * 24 * time.Hour
)

// proofMessage is the NIP-C1 certificate-signed message.
func proofMessage(createdAt, expiry int64, pubkey string) []byte {
	return []byte(fmt.Sprintf("Verifying at %d until %d that I control the following Nostr public key: %s", createdAt, expiry, pubkey))
}

func proofWindow(createdAt, expiry int64, now time.Time) error {
	if d := now.Sub(time.Unix(createdAt, 0)); d > proofSkew || d < -proofSkew {
		return errors.New("proof created_at is not near the current time")
	}
	if expiry <= createdAt {
		return errors.New("proof expiry is not after created_at")
	}
	if time.Duration(expiry-createdAt)*time.Second > proofMaxLife {
		return errors.New("proof expiry is more than two years away")
	}
	return nil
}

// signProof signs a NIP-C1 message: ECDSA with SHA-256 as ASN.1 DER, or
// RSASSA-PKCS1-v1_5 with SHA-256.
func signProof(pkcs8, message []byte) ([]byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(message)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, sum[:])
	default:
		return nil, errMechanism
	}
}

func signPKCS8(pkcs8 []byte, mechanism uint32, data []byte) ([]byte, error) {
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return signRSA(k, mechanism, data)
	case *ecdsa.PrivateKey:
		return signEC(k, mechanism, data)
	default:
		return nil, errMechanism
	}
}

func signRSA(key *rsa.PrivateKey, mechanism uint32, data []byte) ([]byte, error) {
	switch mechanism {
	case ckmRSAPKCS:
		return rsa.SignPKCS1v15(rand.Reader, key, 0, data)
	case ckmSHA256RSAPKCS:
		return signPKCS1(key, crypto.SHA256, sha256.New(), data)
	case ckmSHA384RSAPKCS:
		return signPKCS1(key, crypto.SHA384, sha512.New384(), data)
	case ckmSHA512RSAPKCS:
		return signPKCS1(key, crypto.SHA512, sha512.New(), data)
	case ckmSHA256RSAPKCSPSS:
		return signPSS(key, crypto.SHA256, sha256.New(), data)
	case ckmSHA384RSAPKCSPSS:
		return signPSS(key, crypto.SHA384, sha512.New384(), data)
	case ckmSHA512RSAPKCSPSS:
		return signPSS(key, crypto.SHA512, sha512.New(), data)
	default:
		return nil, errMechanism
	}
}

func signPKCS1(key *rsa.PrivateKey, h crypto.Hash, sum hash.Hash, data []byte) ([]byte, error) {
	sum.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, key, h, sum.Sum(nil))
}

func signPSS(key *rsa.PrivateKey, h crypto.Hash, sum hash.Hash, data []byte) ([]byte, error) {
	sum.Write(data)
	return rsa.SignPSS(rand.Reader, key, h, sum.Sum(nil), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func signEC(key *ecdsa.PrivateKey, mechanism uint32, data []byte) ([]byte, error) {
	var hashed []byte
	switch mechanism {
	case ckmECDSA:
		hashed = data
	case ckmECDSASHA256:
		sum := sha256.Sum256(data)
		hashed = sum[:]
	case ckmECDSASHA384:
		sum := sha512.Sum384(data)
		hashed = sum[:]
	case ckmECDSASHA512:
		sum := sha512.Sum512(data)
		hashed = sum[:]
	default:
		return nil, errMechanism
	}
	if len(hashed) == 0 {
		return nil, errMechanism
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
	if err != nil {
		return nil, err
	}
	return rawECDSA(key.Curve, r, s), nil
}

func rawECDSA(curve elliptic.Curve, r, s *big.Int) []byte {
	size := (curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

func publicFields(cert *x509.Certificate) (kind byte, a, b []byte, err error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N == nil || pub.E <= 1 {
			return 0, nil, nil, errors.New("android certificate key is invalid")
		}
		e := big.NewInt(int64(pub.E)).Bytes()
		return keyRSA, pub.N.Bytes(), e, nil
	case *ecdsa.PublicKey:
		oid, err := curveOID(pub.Curve)
		if err != nil {
			return 0, nil, nil, err
		}
		params, err := asn1.Marshal(oid)
		if err != nil {
			return 0, nil, nil, err
		}
		return keyEC, params, uncompressed(pub), nil
	default:
		return 0, nil, nil, errors.New("android certificate key must be RSA or EC")
	}
}

func curveOID(curve elliptic.Curve) (asn1.ObjectIdentifier, error) {
	if curve == nil || curve.Params() == nil {
		return nil, errors.New("android certificate curve is unsupported")
	}
	switch curve.Params().Name {
	case "P-256":
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, nil
	case "P-384":
		return asn1.ObjectIdentifier{1, 3, 132, 0, 34}, nil
	case "P-521":
		return asn1.ObjectIdentifier{1, 3, 132, 0, 35}, nil
	default:
		return nil, errors.New("android certificate curve is unsupported")
	}
}

func uncompressed(pub *ecdsa.PublicKey) []byte {
	size := (pub.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 1+2*size)
	out[0] = 0x04
	pub.X.FillBytes(out[1 : 1+size])
	pub.Y.FillBytes(out[1+size:])
	return out
}

func mechanismName(v uint32) string {
	switch v {
	case ckmRSAPKCS:
		return "CKM_RSA_PKCS"
	case ckmSHA256RSAPKCS:
		return "CKM_SHA256_RSA_PKCS"
	case ckmSHA384RSAPKCS:
		return "CKM_SHA384_RSA_PKCS"
	case ckmSHA512RSAPKCS:
		return "CKM_SHA512_RSA_PKCS"
	case ckmSHA256RSAPKCSPSS:
		return "CKM_SHA256_RSA_PKCS_PSS"
	case ckmSHA384RSAPKCSPSS:
		return "CKM_SHA384_RSA_PKCS_PSS"
	case ckmSHA512RSAPKCSPSS:
		return "CKM_SHA512_RSA_PKCS_PSS"
	case ckmECDSA:
		return "CKM_ECDSA"
	case ckmECDSASHA256:
		return "CKM_ECDSA_SHA256"
	case ckmECDSASHA384:
		return "CKM_ECDSA_SHA384"
	case ckmECDSASHA512:
		return "CKM_ECDSA_SHA512"
	default:
		return "unknown"
	}
}
