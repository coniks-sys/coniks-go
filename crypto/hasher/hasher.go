package hasher

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/crypto"
)

// Hash represents the output of the used hash function.
type Hash [crypto.DefaultHashSizeByte]byte

// PADHasher provides hash functions for the PAD implementations.
type PADHasher interface {
	// ID returns the name of the cryptographic hash function.
	ID() string
	// Size returns the size of the hash output in bytes.
	Size() int
	// Digest hashes all passed byte slices. The passed slices won't be mutated.
	Digest(ms ...[]byte) []byte
	treeHasher
}

// treeHasher provides hash functions for tree implementations.
type treeHasher interface {
	// HashInterior computes the hash of an interior node as: H(left || right)
	HashInterior(left, right []byte) []byte

	// HashLeaf computes the hash of a user leaf node as:
	// H(Identifier || nonce || index || level || commit)
	HashLeaf(nonce []byte, index []byte, level uint32, data []byte) []byte

	// HashEmpty computes the hash of an empty leaf node as:
	// H(Identifier || nonce || index || level)
	HashEmpty(nonce []byte, index []byte, level uint32) []byte
}

var hashers = make(map[string]PADHasher)

// RegisterHasher registers a hasher for use.
func RegisterHasher(h string, f func() PADHasher) {
	if _, ok := hashers[h]; ok {
		panic(fmt.Sprintf("RegisterHasher(%v) is already registered", h))
	}
	hashers[h] = f()
}

// Hasher returns a PADHasher.
func Hasher(h string) (PADHasher, error) {
	if f, ok := hashers[h]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("Hasher(%v) is unknown hasher", h)
}
