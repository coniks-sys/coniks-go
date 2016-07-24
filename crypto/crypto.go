package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	HashSizeByte   = 32
	HashID         = "SHAKE128"
	PrivateKeySize = 64
)

type SigningKey ed25519.PrivateKey
type VerifKey ed25519.PublicKey

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

func (key SigningKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(key), message)
}

func (key SigningKey) Public() (VerifKey, bool) {
      pk, ok := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
      return VerifKey(pk), ok
}

func (pk VerifKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk), message, sig)
}

// MakeRand generates a random slice of byte and hashes it.
func MakeRand() ([]byte, error) {
	r := make([]byte, HashSizeByte)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	// Do not directly reveal bytes from rand.Read on the wire
	return Digest(r), nil
}
