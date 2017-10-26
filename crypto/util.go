package crypto

import (
	"bytes"
	"crypto/rand"

	"crypto/sha512"
)

// DefaultHashSizeByte is the size of the hash function in bytes.
const DefaultHashSizeByte = sha512.Size256

// digest hashes all passed byte slices.
// The passed slices won't be mutated.
func digest(ms ...[]byte) []byte {
	h := sha512.New512_256()
	for _, m := range ms {
		h.Write(m)
	}
	return h.Sum(nil)
}

// MakeRand returns a random slice of bytes.
// It returns an error if there was a problem while generating
// the random slice.
// It is different from the 'standard' random byte generation as it
// hashes its output before returning it; by hashing the system's
// PRNG output before it is send over the wire, we aim to make the
// random output less predictable (even if the system's PRNG isn't
// as unpredictable as desired).
// See https://trac.torproject.org/projects/tor/ticket/17694
func MakeRand() ([]byte, error) {
	r := make([]byte, DefaultHashSizeByte)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	// Do not directly reveal bytes from rand.Read on the wire
	return digest(r), nil
}

// Commit can be used to create a cryptographic commit to some value (use
// NewCommit() for this purpose.
type Commit struct {
	// Salt is a cryptographic salt which will be hashed in addition
	// to the value.
	Salt []byte
	// Value is the actual value to commit to.
	Value []byte
}

// NewCommit creates a new cryptographic commit to the passed byte slices
// stuff (which won't be mutated). It creates a random salt before
// committing to the values.
func NewCommit(stuff ...[]byte) (*Commit, error) {
	salt, err := MakeRand()
	if err != nil {
		return nil, err
	}
	return &Commit{
		Salt:  salt,
		Value: digest(append([][]byte{salt}, stuff...)...),
	}, nil
}

// Verify verifies that the underlying commit c was a commit to the passed
// byte slices stuff (which won't be mutated).
func (c *Commit) Verify(stuff ...[]byte) bool {
	return bytes.Equal(c.Value, digest(append([][]byte{c.Salt}, stuff...)...))
}
