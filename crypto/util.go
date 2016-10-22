package crypto

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

const (
	// HashSizeByte is the used hash's value size in bytes.
	HashSizeByte = 32
	// HashID identifies the used hash as a string.
	HashID = "SHAKE128"
)

// Digest hashes all passed byte slice and hashes them.
// The passed slices won't be mutated.
func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, HashSizeByte)
	h.Read(ret)
	return ret
}

// MakeRand returns a random slice of byte.
// It returns an error if there was a problem while generating the random slice.
// It is different from the 'standard' random byte generation as it hashes its
// output before returning it.
func MakeRand() ([]byte, error) {
	r := make([]byte, HashSizeByte)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	// Do not directly reveal bytes from rand.Read on the wire
	return Digest(r), nil
}

// Commit can be used to create a cryptographic commit to some value (use
// `NewCommit` for this purpose.
type Commit struct {
	// Salt is a cryptographic salt which will be hashed additionally to the
	// value.
	Salt []byte
	// Value is the actual value to commit to.
	Value []byte
}

// NewCommit creates a new cryptographic commit to the passed byte slices
// `stuff` (which won't be mutated). It creates a random salt before committing
// to the values.
func NewCommit(stuff ...[]byte) (*Commit, error) {
	salt, err := MakeRand()
	if err != nil {
		return nil, err
	}
	return &Commit{
		Salt:  salt,
		Value: Digest(append([][]byte{salt}, stuff...)...),
	}, nil
}

// Verify verifies that the underlying commit `c` was a commit to the passed
// data `stuff` (which won't be mutated).
func (c *Commit) Verify(stuff ...[]byte) bool {
	return bytes.Equal(c.Value, Digest(append([][]byte{c.Salt}, stuff...)...))
}
