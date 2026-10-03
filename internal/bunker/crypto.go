package bunker

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	gonostr "github.com/nbd-wtf/go-nostr"
	"golang.org/x/crypto/hkdf"
)

func publicKeyHex(key []byte) (string, error) {
	pub, priv, err := xOnly(key)
	if err != nil {
		return "", err
	}
	priv.Zero()
	return pub, nil
}

func signNostr(evt *gonostr.Event, key []byte) error {
	if evt.Tags == nil {
		evt.Tags = make(gonostr.Tags, 0)
	}
	pub, priv, err := xOnly(key)
	if err != nil {
		return err
	}
	defer priv.Zero()
	evt.PubKey = pub
	hash := sha256.Sum256(evt.Serialize())
	sig, err := schnorr.Sign(priv, hash[:], schnorr.FastSign())
	if err != nil {
		return errors.New("sign event failed")
	}
	evt.ID = hex.EncodeToString(hash[:])
	evt.Sig = hex.EncodeToString(sig.Serialize())
	return nil
}

func xOnly(key []byte) (string, *btcec.PrivateKey, error) {
	if len(key) != 32 {
		return "", nil, errors.New("invalid Nostr private key")
	}
	priv, pub := btcec.PrivKeyFromBytes(key)
	compressed := pub.SerializeCompressed()
	if len(compressed) != 33 {
		priv.Zero()
		return "", nil, errors.New("invalid Nostr private key")
	}
	return hex.EncodeToString(compressed[1:]), priv, nil
}

func nip04Shared(pub string, key []byte) ([]byte, error) {
	priv, pubKey, err := peer(pub, key)
	if err != nil {
		return nil, err
	}
	defer priv.Zero()
	return btcec.GenerateSharedSecret(priv, pubKey), nil
}

func nip44Conversation(pub string, key []byte) ([32]byte, error) {
	var out [32]byte
	shared, err := nip44Shared(pub, key)
	if err != nil {
		return out, err
	}
	defer wipe32(&shared)
	buf := hkdf.Extract(sha256.New, shared[:], []byte("nip44-v2"))
	defer clear(buf)
	copy(out[:], buf)
	return out, nil
}

func nip44Shared(pub string, key []byte) ([32]byte, error) {
	var shared [32]byte
	priv, pubKey, err := peer(pub, key)
	if err != nil {
		return shared, err
	}
	defer priv.Zero()
	var point, result secp256k1.JacobianPoint
	defer func() {
		point = secp256k1.JacobianPoint{}
		result = secp256k1.JacobianPoint{}
	}()
	pubKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&priv.Key, &point, &result)
	result.ToAffine()
	result.X.PutBytesUnchecked(shared[:])
	return shared, nil
}

func peer(pub string, key []byte) (*btcec.PrivateKey, *btcec.PublicKey, error) {
	if len(key) != 32 {
		return nil, nil, errors.New("invalid Nostr private key")
	}
	raw, err := hex.DecodeString("02" + pub)
	if err != nil {
		return nil, nil, errors.New("invalid public key")
	}
	defer clear(raw)
	pubKey, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, nil, errors.New("invalid public key")
	}
	priv, _ := btcec.PrivKeyFromBytes(key)
	return priv, pubKey, nil
}
