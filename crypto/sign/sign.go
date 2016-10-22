package sign

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/ed25519"
)

const (
	// PrivateKeySize is the size of private-key in bytes.
	PrivateKeySize = 64
	// PublicKeySize is the size of the public-key in bytes.
	PublicKeySize = 32
	// SignatureSize is the size of the created signature in bytes.
	SignatureSize = 64
)

// PrivateKey wraps the underlying private-key (ed25519.PrivateKey).
// It provides some wrapper methods: `Sign()`, `Public()`
type PrivateKey ed25519.PrivateKey

// PublicKey wraps the underlying public-key type. It can be used to verify a
// signature which was created by using a corresponding `PrivateKey`
type PublicKey ed25519.PublicKey

// GenerateKey generates and returns a fresh random private-key, from which the
// corresponding public-key can be derived (by calling `Public()` on it).
// It will use the passed `io.Reader` `rnd` as a source of randomness, or, if
// `rnd` is nil it will use a sane default (`rand.Reader`).
//
// It returns an error if the key couldn't be properly generated. This, for
// example can happen if there isn't enough entropy for the randomness.
func GenerateKey(rnd io.Reader) (PrivateKey, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	_, sk, err := ed25519.GenerateKey(rnd)
	return PrivateKey(sk), err
}

// Sign returns a signature on the passed byte-slice `message` using the
// underlying private-key.
// The passed slice won't be modified.
func (key PrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(key), message)
}

// Public derives the corresponding public-key from the underlying private-key.
// It returns the derived key ,if possible, and a boolean flag which indicates if
// the operations to derive the public-key were successful.
func (key PrivateKey) Public() (PublicKey, bool) {
	pk, ok := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	return PublicKey(pk), ok
}

// Verify verifies a signature `sig` on `message` using the underlying
// public-key. It returns true if and only if the signature is valid.
// The passed slices aren't modified.
func (pk PublicKey) Verify(message, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk), message, sig)
}
