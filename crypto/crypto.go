package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	HashSizeByte = 32
	HashID       = "SHAKE128"
)

type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, HashSizeByte)
	h.Read(ret)
	return ret
}

func GenerateKey() KeyPair {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	return KeyPair{
		PrivateKey: sk,
		PublicKey:  pk,
	}
}

func Sign(key KeyPair, message []byte) []byte {
	return ed25519.Sign(key.PrivateKey, message)
}

func Verify(key KeyPair, message, sig []byte) bool {
	return ed25519.Verify(key.PublicKey, message, sig)
}
