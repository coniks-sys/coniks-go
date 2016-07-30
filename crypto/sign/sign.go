package sign

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
)

const (
	PrivateKeySize = 64
	PublicKeySize  = 32
)

type PrivateKey ed25519.PrivateKey
type PublicKey ed25519.PublicKey

func GenerateKey() (PrivateKey, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	return PrivateKey(sk), err
}

func (key *PrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(*key), message)
}

func (key *PrivateKey) Public() (PublicKey, bool) {
	pk, ok := ed25519.PrivateKey(*key).Public().(ed25519.PublicKey)
	return PublicKey(pk), ok
}

func (pk *PublicKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(*pk), message, sig)
}
