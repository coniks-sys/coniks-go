package crypto

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

const (
	HashSizeByte = 32
	HashID       = "SHAKE128"
)

func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake128()
	for _, m := range ms {
		h.Write(m)
	}
	ret := make([]byte, HashSizeByte)
	h.Read(ret)
	return ret
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

type Commit struct {
	Salt  []byte
	Value []byte
}

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

func (c *Commit) Verify(stuff ...[]byte) bool {
	return bytes.Equal(c.Value, Digest(append([][]byte{c.Salt}, stuff...)...))
}

func (c *Commit) Clone() *Commit {
	return &Commit{Salt: c.Salt, Value: c.Value}
}
