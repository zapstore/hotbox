// Framing for the signing socket. pkcs11/hotbox.c speaks the same bytes.
//
//	request and response:
//	  u8  version = 1
//	  u8  op or status
//	  u32 body length, big endian
//	  body
//
// info request body: u16 pin length, pin bytes.
// sign request body: u16 pin length, pin, u32 mechanism, u32 data length, data.
// proof request body: u16 pin length, pin, u64 created_at, u64 expiry.
//
// info response body, after status 0:
//
//	u16 alias length, alias
//	u8  key type (1 RSA, 2 EC)
//	u16 a length, a (RSA modulus or EC parameters DER)
//	u16 b length, b (RSA exponent or uncompressed EC point)
//	u8  certificate count
//	repeated: u32 der length, der, u16 subject, subject,
//	          u16 issuer, issuer, u16 serial, serial
//
// sign response body, after status 0: u32 signature length, signature.
//
// proof response body, after status 0: 32-byte Nostr public key,
// 32-byte certificate SHA-256, u32 signature length, signature.
// The signature is the NIP-C1 certificate signature over the proof message
// for that public key: ASN.1 DER ECDSA or PKCS#1 v1.5, both with SHA-256.
package token

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	protoVersion = 1
	opInfo       = 1
	opSign       = 2
	opProof      = 3

	statusOK        = 0
	statusPIN       = 1
	statusMechanism = 2
	statusBad       = 3
	statusFailed    = 4

	keyRSA = 1
	keyEC  = 2

	maxFrame = 1 << 20
)

func writeFrame(w io.Writer, kind byte, body []byte) error {
	if len(body) > maxFrame {
		return errors.New("signer frame is too large")
	}
	var hdr [6]byte
	hdr[0] = protoVersion
	hdr[1] = kind
	binary.BigEndian.PutUint32(hdr[2:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0] != protoVersion {
		return 0, nil, errors.New("signer frame version is unsupported")
	}
	n := binary.BigEndian.Uint32(hdr[2:])
	if n > maxFrame {
		return 0, nil, errors.New("signer frame is too large")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[1], body, nil
}

func pinBody(pin string) ([]byte, error) {
	if len(pin) > 64 {
		return nil, errors.New("pin is too long")
	}
	buf := make([]byte, 2+len(pin))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(pin)))
	copy(buf[2:], pin)
	return buf, nil
}

func takePin(body []byte) (string, []byte, error) {
	if len(body) < 2 {
		return "", nil, errors.New("signer request is short")
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if n != 32 || len(body) < n {
		return "", nil, errors.New("signer pin is invalid")
	}
	return string(body[:n]), body[n:], nil
}
