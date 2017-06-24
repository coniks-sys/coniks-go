package hashers

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/crypto"
)

// Hash represents the output of the used hash function.
type Hash [crypto.DefaultHashSizeByte]byte

// PADHasher provides hash functions for the PAD implementations,
// and defines the way empty / node / leaf hashes of the underlying tree
// are constructed.
type PADHasher interface {
	// ID returns the name of the cryptographic hash function.
	ID() string
	// Size returns the size of the hash output in bytes.
	Size() int
	// Digest provides a universal hash function which
	// hashes all passed byte slices. The passed slices won't be mutated.
	Digest(ms ...[]byte) []byte

	// HashInterior computes the hash of an interior node.
	HashInterior(left, right []byte) []byte

	// HashLeaf computes the hash of a user leaf node.
	HashLeaf(nonce []byte, index []byte, level uint32, data []byte) []byte

	// HashEmpty computes the hash of an empty leaf node.
	HashEmpty(nonce []byte, index []byte, level uint32) []byte
}

var hashers = make(map[string]PADHasher)

// RegisterHasher registers a hasher for use.
func RegisterHasher(h string, f func() PADHasher) {
	if _, ok := hashers[h]; ok {
		panic(fmt.Sprintf("%s is already registered", h))
	}
	hashers[h] = f()
}

// NewPADHasher returns a registered PADHasher identified by the given string.
// If no such PADHasher exists, it returns an error.
func NewPADHasher(h string) (PADHasher, error) {
	if f, ok := hashers[h]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("%s is an unknown hasher", h)
}
