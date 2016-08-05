package crypto

import (
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
