package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	PrivateIndexSize = 32
	HashSizeByte     = 32
	HashID           = "SHAKE128"
	PrivateKeySize   = 64
)

type SigningKey ed25519.PrivateKey

func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, HashSizeByte)
	h.Read(ret)
	return ret
}

func GenerateKey() (SigningKey, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	return SigningKey(sk), err
}

func Sign(key SigningKey, message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(key), message)
}

func Verify(key SigningKey, message, sig []byte) bool {
	pk, ok := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(pk, message, sig)
}
