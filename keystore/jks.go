package keystore

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// JKS wraps each private key as this Sun algorithm, then XOR-streams it with
// SHA-1(password, previous), where the first previous value is a 20-byte salt.
var jksKeyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}

type jksAlgo struct {
	OID    asn1.ObjectIdentifier
	Params asn1.RawValue `asn1:"optional"`
}

type jksWrapped struct {
	Algo jksAlgo
	Body []byte
}

func parseJKS(data []byte, storePassword, keyPassword string) ([]Entry, error) {
	if len(data) < 20 {
		return nil, errCorrupt()
	}
	body, mac := data[:len(data)-20], data[len(data)-20:]
	sum := sha1.New()
	pw := utf16BE(storePassword)
	defer wipe(pw)
	sum.Write(pw)
	sum.Write([]byte("Mighty Aphrodite"))
	sum.Write(body)
	if subtle.ConstantTimeCompare(sum.Sum(nil), mac) != 1 {
		return nil, ErrPassword
	}

	r := body
	magic, r, err := take32(r)
	if err != nil || magic != 0xfeedfeed {
		return nil, errCorrupt()
	}
	version, r, err := take32(r)
	if err != nil || (version != 1 && version != 2) {
		return nil, errCorrupt()
	}
	count, r, err := take32(r)
	if err != nil || count > 64 {
		return nil, errCorrupt()
	}
	var out []Entry
	for range count {
		var tag uint32
		tag, r, err = take32(r)
		if err != nil {
			return nil, err
		}
		var alias string
		alias, r, err = takeString(r)
		if err != nil {
			return nil, err
		}
		switch tag {
		case 1:
			entry, rest, err := takeKeyEntry(r, version, alias, keyPassword)
			if err != nil {
				return nil, err
			}
			r = rest
			if entry.Alias != "" {
				out = append(out, entry)
			}
		case 2:
			r, err = skipCertEntry(r, version)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errCorrupt()
		}
	}
	if len(r) != 0 {
		return nil, errCorrupt()
	}
	if len(out) == 0 {
		return nil, errors.New("keystore has no private key")
	}
	return out, nil
}

func takeKeyEntry(r []byte, version uint32, alias, keyPassword string) (Entry, []byte, error) {
	_, r, err := take64(r) // creation time
	if err != nil {
		return Entry{}, nil, err
	}
	var n uint32
	n, r, err = take32(r)
	if err != nil || n > 1<<16 {
		return Entry{}, nil, errCorrupt()
	}
	blob, r, err := take(r, int(n))
	if err != nil {
		return Entry{}, nil, err
	}
	var chainCount uint32
	chainCount, r, err = take32(r)
	if err != nil || chainCount == 0 || chainCount > 8 {
		return Entry{}, nil, errCorrupt()
	}
	certs := make([][]byte, 0, chainCount)
	for range chainCount {
		var der []byte
		der, r, err = takeCert(r, version)
		if err != nil {
			return Entry{}, nil, err
		}
		certs = append(certs, der)
	}
	pkcs8, err := decryptJKSKey(blob, keyPassword)
	if err != nil {
		return Entry{}, nil, err
	}
	entry, err := finish(alias, pkcs8, certs)
	wipe(pkcs8)
	if err != nil {
		return Entry{}, nil, err
	}
	return entry, r, nil
}

func skipCertEntry(r []byte, version uint32) ([]byte, error) {
	var err error
	_, r, err = take64(r)
	if err != nil {
		return nil, err
	}
	_, r, err = takeCert(r, version)
	return r, err
}

func takeCert(r []byte, version uint32) ([]byte, []byte, error) {
	var err error
	if version == 2 {
		_, r, err = takeString(r)
		if err != nil {
			return nil, nil, err
		}
	}
	n, r, err := take32(r)
	if err != nil || n == 0 || n > 1<<16 {
		return nil, nil, errCorrupt()
	}
	der, r, err := take(r, int(n))
	return der, r, err
}

func decryptJKSKey(blob []byte, password string) ([]byte, error) {
	var wrapped jksWrapped
	rest, err := asn1.Unmarshal(blob, &wrapped)
	if err != nil || len(rest) != 0 || !wrapped.Algo.OID.Equal(jksKeyOID) {
		return nil, errCorrupt()
	}
	body := wrapped.Body
	if len(body) < 40 {
		return nil, errCorrupt()
	}
	check := body[len(body)-20:]
	enc := body[20 : len(body)-20]
	pw := utf16BE(password)
	defer wipe(pw)
	plain := make([]byte, len(enc))
	digest := make([]byte, 20)
	copy(digest, body[:20])
	sum := sha1.New()
	for off := 0; off < len(enc); {
		sum.Reset()
		sum.Write(pw)
		sum.Write(digest)
		digest = sum.Sum(digest[:0])
		n := copy(plain[off:], digest)
		for i := range n {
			plain[off+i] ^= enc[off+i]
		}
		off += n
	}
	sum.Reset()
	sum.Write(pw)
	sum.Write(plain)
	if subtle.ConstantTimeCompare(sum.Sum(nil), check) != 1 {
		wipe(plain)
		return nil, ErrKeyPassword
	}
	return plain, nil
}

func utf16BE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.BigEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func take(r []byte, n int) ([]byte, []byte, error) {
	if n < 0 || len(r) < n {
		return nil, nil, errCorrupt()
	}
	return r[:n], r[n:], nil
}

func take32(r []byte) (uint32, []byte, error) {
	b, rest, err := take(r, 4)
	if err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint32(b), rest, nil
}

func take64(r []byte) (uint64, []byte, error) {
	b, rest, err := take(r, 8)
	if err != nil {
		return 0, nil, err
	}
	return binary.BigEndian.Uint64(b), rest, nil
}

func takeString(r []byte) (string, []byte, error) {
	if len(r) < 2 {
		return "", nil, errCorrupt()
	}
	n := int(binary.BigEndian.Uint16(r))
	b, rest, err := take(r[2:], n)
	if err != nil || n > 256 {
		return "", nil, errCorrupt()
	}
	return string(b), rest, nil
}

func errCorrupt() error {
	return errors.New("keystore is corrupt")
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
