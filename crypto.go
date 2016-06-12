package merkletree

import (
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	HashSizeByte   = 32
	HashID         = "SHAKE128"
	PrivateKeySize = ed25519.PrivateKeySize
	PublicKeySize  = ed25519.PublicKeySize
	SignatureSize  = ed25519.SignatureSize
)

func Digest(ms ...[]byte) []byte {
	h := sha3.NewShake256()
	for _, m := range ms {
		h.Write(m)
	}
	var ret [HashSizeByte]byte
	h.Read(ret[:])
	return ret[:]
}

func Sign(privateKey []byte, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(publicKey []byte, message, sig []byte) bool {
	return ed25519.Verify(publicKey, message, sig)
}
