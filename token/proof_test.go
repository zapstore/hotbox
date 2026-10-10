package token

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

const testPubkey = "78ce6faa72264387284e647ba6938995735ec8c7d5c5a65737e55130f026307d"

func TestProofOverSocket(t *testing.T) {
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
		Alias:  "hotbox",
		PIN:    pin,
		Certs:  [][]byte{der},
		Pubkey: testPubkey,
		Use: func(_ context.Context, fn func([]byte) error) error {
			return fn(pkcs8)
		},
	}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	now := time.Now().Unix()
	tests := []struct {
		name      string
		pin       string
		createdAt int64
		expiry    int64
		status    byte
	}{
		{"valid", string(pin[:]), now, now + 365*24*3600, statusOK},
		{"wrong pin", "00000000000000000000000000000000", now, now + 3600, statusPIN},
		{"old created_at", string(pin[:]), now - 3600, now + 3600, statusBad},
		{"expiry before created_at", string(pin[:]), now, now - 1, statusBad},
		{"expiry beyond two years", string(pin[:]), now, now + 3*365*24*3600, statusBad},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t, tok.Path)
			defer conn.Close()
			req, _ := pinBody(tc.pin)
			req = binary.BigEndian.AppendUint64(req, uint64(tc.createdAt))
			req = binary.BigEndian.AppendUint64(req, uint64(tc.expiry))
			if err := writeFrame(conn, opProof, req); err != nil {
				t.Fatal(err)
			}
			status, body, err := readFrame(conn)
			if err != nil || status != tc.status {
				t.Fatalf("status %d err %v, want %d", status, err, tc.status)
			}
			if tc.status != statusOK {
				return
			}
			if len(body) < 68 || hex.EncodeToString(body[:32]) != testPubkey {
				t.Fatalf("body does not start with the vault pubkey")
			}
			certHash := sha256.Sum256(der)
			if !bytes.Equal(body[32:64], certHash[:]) {
				t.Fatal("certificate hash mismatch")
			}
			n := binary.BigEndian.Uint32(body[64:68])
			sig := body[68:]
			if int(n) != len(sig) {
				t.Fatalf("signature length %d, field %d", len(sig), n)
			}
			sum := sha256.Sum256(proofMessage(tc.createdAt, tc.expiry, testPubkey))
			if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
				t.Fatal("proof signature did not verify as ASN.1 ECDSA over SHA-256")
			}
		})
	}
}

func TestProofWithoutPubkey(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tok := startSigner(t, ctx, t.Name())
	defer tok.Close()
	conn := dial(t, tok.Path)
	defer conn.Close()
	req, _ := pinBody("0123456789abcdef0123456789abcdef")
	now := time.Now().Unix()
	req = binary.BigEndian.AppendUint64(req, uint64(now))
	req = binary.BigEndian.AppendUint64(req, uint64(now+3600))
	if err := writeFrame(conn, opProof, req); err != nil {
		t.Fatal(err)
	}
	if status, _, err := readFrame(conn); err != nil || status != statusBad {
		t.Fatalf("status %d err %v, want %d", status, err, statusBad)
	}
}
