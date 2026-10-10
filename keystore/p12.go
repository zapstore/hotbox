package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"unicode/utf16"

	"golang.org/x/crypto/pbkdf2"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidShroudedKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidCertX509      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidPBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHMACSHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
)

type p12Bag struct {
	id    asn1.ObjectIdentifier
	value []byte
	alias string
}

func parsePKCS12(data []byte, password string) ([]Entry, error) {
	var pfx struct {
		Version  int
		AuthSafe asn1.RawValue
		Mac      asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(data, &pfx)
	if err != nil || len(rest) != 0 || pfx.Version != 3 {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	safeDER, err := dataContent(pfx.AuthSafe.FullBytes)
	if err != nil {
		return nil, err
	}
	bmp := bmpPassword(password)
	if len(pfx.Mac.FullBytes) != 0 && !macOK(pfx.Mac.FullBytes, safeDER, []byte(password), bmp) {
		return nil, ErrPassword
	}
	var infos []asn1.RawValue
	if _, err := asn1.Unmarshal(safeDER, &infos); err != nil {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	var pkcs8 []byte
	var certs [][]byte
	alias := ""
	for _, info := range infos {
		bags, err := bagsFromContent(info.FullBytes, password, bmp)
		if err != nil {
			wipe(pkcs8)
			return nil, err
		}
		for _, bag := range bags {
			switch {
			case bag.id.Equal(oidShroudedKey):
				if pkcs8 != nil {
					wipe(pkcs8)
					return nil, errors.New("keystore has more than one private key")
				}
				pkcs8 = bag.value
				if bag.alias != "" {
					alias = bag.alias
				}
			case bag.id.Equal(oidCertBag):
				certs = append(certs, bag.value)
				if alias == "" {
					alias = bag.alias
				}
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
	if alias == "" {
		alias = aliasFromCert(ordered[0])
	}
	entry, err := finish(alias, pkcs8, ordered)
	wipe(pkcs8)
	if err != nil {
		return nil, err
	}
	return []Entry{entry}, nil
}

func bagsFromContent(full []byte, password string, bmp []byte) ([]p12Bag, error) {
	var info struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	rest, err := asn1.Unmarshal(full, &info)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	body := info.Content.Bytes
	if info.Type.Equal(oidEncryptedData) {
		var enc struct {
			Version int
			Info    struct {
				Type asn1.ObjectIdentifier
				Alg  pkix.AlgorithmIdentifier
				Data []byte `asn1:"tag:0,implicit"`
			}
		}
		if _, err := asn1.Unmarshal(body, &enc); err != nil {
			return nil, errors.New("keystore is not a PKCS#12 file")
		}
		body, err = decryptPBES2(enc.Info.Alg, enc.Info.Data, password, bmp)
		if err != nil {
			return nil, err
		}
	} else if info.Type.Equal(oidData) {
		var octet []byte
		if _, err := asn1.Unmarshal(body, &octet); err != nil {
			return nil, errors.New("keystore is not a PKCS#12 file")
		}
		body = octet
	} else {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	return parseBags(body, password, bmp)
}

func dataContent(full []byte) ([]byte, error) {
	var info struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	rest, err := asn1.Unmarshal(full, &info)
	if err != nil || len(rest) != 0 || !info.Type.Equal(oidData) {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	var octet []byte
	if _, err := asn1.Unmarshal(info.Content.Bytes, &octet); err != nil {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	return octet, nil
}

func parseBags(der []byte, password string, bmp []byte) ([]p12Bag, error) {
	var raws []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raws)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("keystore is not a PKCS#12 file")
	}
	out := make([]p12Bag, 0, len(raws))
	for _, raw := range raws {
		var item struct {
			ID    asn1.ObjectIdentifier
			Value asn1.RawValue   `asn1:"tag:0,explicit"`
			Attrs []asn1.RawValue `asn1:"set,optional"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &item); err != nil {
			return nil, errors.New("keystore is not a PKCS#12 file")
		}
		alias := friendly(item.Attrs)
		switch {
		case item.ID.Equal(oidShroudedKey):
			var epki struct {
				Alg  pkix.AlgorithmIdentifier
				Data []byte
			}
			if _, err := asn1.Unmarshal(item.Value.Bytes, &epki); err != nil {
				return nil, errors.New("keystore is not a PKCS#12 file")
			}
			key, err := decryptPBES2(epki.Alg, epki.Data, password, bmp)
			if err != nil {
				return nil, err
			}
			out = append(out, p12Bag{id: item.ID, value: key, alias: alias})
		case item.ID.Equal(oidCertBag):
			var cert struct {
				ID    asn1.ObjectIdentifier
				Value asn1.RawValue `asn1:"tag:0,explicit"`
			}
			if _, err := asn1.Unmarshal(item.Value.Bytes, &cert); err != nil || !cert.ID.Equal(oidCertX509) {
				return nil, errors.New("keystore certificate is invalid")
			}
			var der []byte
			if _, err := asn1.Unmarshal(cert.Value.Bytes, &der); err != nil {
				der = cert.Value.Bytes
			}
			out = append(out, p12Bag{id: item.ID, value: der, alias: alias})
		}
	}
	return out, nil
}

func friendly(attrs []asn1.RawValue) string {
	for _, raw := range attrs {
		var attr struct {
			ID     asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &attr); err != nil || !attr.ID.Equal(oidFriendlyName) {
			continue
		}
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &inner); err != nil {
			continue
		}
		// BMPString is tag 30. The bytes are UTF-16BE.
		if inner.Tag == 30 && len(inner.Bytes)%2 == 0 {
			units := make([]uint16, len(inner.Bytes)/2)
			for i := range units {
				units[i] = uint16(inner.Bytes[i*2])<<8 | uint16(inner.Bytes[i*2+1])
			}
			name := string(utf16.Decode(units))
			if validAlias(name) == nil {
				return name
			}
		}
	}
	return ""
}

func decryptPBES2(alg pkix.AlgorithmIdentifier, ciphertext []byte, password string, bmp []byte) ([]byte, error) {
	if !alg.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("keystore encryption is unsupported")
	}
	var params struct {
		KDF    pkix.AlgorithmIdentifier
		Cipher pkix.AlgorithmIdentifier
	}
	if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &params); err != nil || !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("keystore encryption is unsupported")
	}
	var kdf struct {
		Salt []byte
		Iter int
		Len  int                      `asn1:"optional"`
		PRF  pkix.AlgorithmIdentifier `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil || kdf.Iter < 1 || len(kdf.Salt) == 0 {
		return nil, errors.New("keystore encryption is unsupported")
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.Cipher.Parameters.FullBytes, &iv); err != nil || len(iv) != aes.BlockSize {
		return nil, errors.New("keystore encryption is unsupported")
	}
	keyLen := 32
	if params.Cipher.Algorithm.Equal(oidAES128CBC) {
		keyLen = 16
	} else if !params.Cipher.Algorithm.Equal(oidAES256CBC) {
		return nil, errors.New("keystore encryption is unsupported")
	}
	if kdf.Len != 0 {
		keyLen = kdf.Len
	}
	prf := sha256.New
	if kdf.PRF.Algorithm != nil && !kdf.PRF.Algorithm.Equal(oidHMACSHA256) {
		if kdf.PRF.Algorithm.Equal(oidSHA1) || kdf.PRF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}) {
			prf = sha1.New
		} else {
			return nil, errors.New("keystore encryption is unsupported")
		}
	}
	for _, secret := range [][]byte{[]byte(password), bmp} {
		key := pbkdf2.Key(secret, kdf.Salt, kdf.Iter, keyLen, prf)
		plain, err := aesCBC(key, iv, ciphertext)
		if err == nil && len(plain) > 0 && plain[0] == 0x30 {
			return plain, nil
		}
	}
	return nil, ErrPassword
}

func aesCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("keystore encryption is unsupported")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	n := int(plain[len(plain)-1])
	if n == 0 || n > aes.BlockSize || n > len(plain) {
		return nil, ErrPassword
	}
	if !bytes.Equal(plain[len(plain)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, ErrPassword
	}
	return plain[:len(plain)-n], nil
}

func macOK(macDER, content, utf8pw, bmp []byte) bool {
	var mac struct {
		Digest struct {
			Alg    pkix.AlgorithmIdentifier
			Digest []byte
		}
		Salt []byte
		Iter int `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(macDER, &mac); err != nil || len(mac.Digest.Digest) == 0 || len(mac.Salt) == 0 {
		return false
	}
	if mac.Iter == 0 {
		mac.Iter = 1
	}
	var h func() hash.Hash
	switch {
	case mac.Digest.Alg.Algorithm.Equal(oidSHA256):
		h = sha256.New
	case mac.Digest.Alg.Algorithm.Equal(oidSHA1):
		h = sha1.New
	default:
		return false
	}
	size := h().Size()
	for _, id := range []byte{3, 1} {
		key := pkcs12KDF(h, size, 64, mac.Salt, bmp, mac.Iter, id, size)
		m := hmac.New(h, key)
		m.Write(content)
		if hmac.Equal(m.Sum(nil), mac.Digest.Digest) {
			return true
		}
	}
	key := pbkdf2.Key(utf8pw, mac.Salt, mac.Iter, size, h)
	m := hmac.New(h, key)
	m.Write(content)
	return hmac.Equal(m.Sum(nil), mac.Digest.Digest)
}

func bmpPassword(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, len(units)*2+2)
	for i, u := range units {
		out[i*2] = byte(u >> 8)
		out[i*2+1] = byte(u)
	}
	return out
}

// pkcs12KDF is the RFC 7292 appendix B key derivation.
func pkcs12KDF(newHash func() hash.Hash, u, v int, salt, password []byte, iterations int, id byte, size int) []byte {
	h := newHash()
	D := bytes.Repeat([]byte{id}, v)
	I := append(stretch(salt, v), stretch(password, v)...)
	var out []byte
	for len(out) < size {
		h.Reset()
		h.Write(D)
		h.Write(I)
		A := h.Sum(nil)
		for range iterations - 1 {
			h.Reset()
			h.Write(A)
			A = h.Sum(nil)
		}
		out = append(out, A...)
		B := stretch(A, v)
		for off := 0; off+v <= len(I); off += v {
			add(I[off:off+v], B)
		}
	}
	return out[:size]
}

func stretch(pattern []byte, v int) []byte {
	if len(pattern) == 0 {
		return nil
	}
	n := v * ((len(pattern) + v - 1) / v)
	out := make([]byte, n)
	for i := range out {
		out[i] = pattern[i%len(pattern)]
	}
	return out
}

func add(dst, b []byte) {
	carry := 1 // the RFC adds B + 1
	for i := len(dst) - 1; i >= 0; i-- {
		n := int(dst[i]) + int(b[i]) + carry
		dst[i] = byte(n)
		carry = n >> 8
	}
}
