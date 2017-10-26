// TODO(huyvq): Remove package import.
// Other package shouldn't need to import this package,
// instead they should insert `hashers` and import this
// package using a blank import name.
// Should be adressed in #06.

package coniks

import (
	"crypto"

	"github.com/coniks-sys/coniks-go/crypto/hashers"
	"github.com/coniks-sys/coniks-go/utils"
)

func init() {
	hashers.RegisterHasher(CONIKS_Hash_SHA512_256, New)
}

const (
	// CONIKS_Hash_SHA512_256 is the identity of the hashing strategy
	// specified in the Coniks paper with SHA512_256 as the hash algorithm.
	CONIKS_Hash_SHA512_256 = "CONIKS_Hash_SHA512_256"

	emptyIdentifier = 'E'
	leafIdentifier  = 'L'
)

type hasher struct {
	crypto.Hash
}

// New returns an instance of CONIKS_Hash_SHA512_256.
func New() hashers.PADHasher {
	return &hasher{Hash: crypto.SHA512_256}
}

func (ch *hasher) Digest(ms ...[]byte) []byte {
	h := ch.New()
	for _, m := range ms {
		h.Write(m)
	}
	return h.Sum(nil)
}

func (hasher) ID() string {
	return CONIKS_Hash_SHA512_256
}

func (ch *hasher) Size() int {
	return ch.Size()
}

// HashInterior computes the hash of an interior node as: H(left || right).
func (ch *hasher) HashInterior(left, right []byte) []byte {
	return ch.Digest(left, right)
}

// HashLeaf computes the hash of a user leaf node as:
// H(Identifier || nonce || index || level || commit).
func (ch *hasher) HashLeaf(nonce []byte, index []byte, level uint32, commit []byte) []byte {
	return ch.Digest(
		[]byte{leafIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
		commit,
	)
}

// HashEmpty computes the hash of an empty leaf node as:
// H(Identifier || nonce || index || level).
func (ch *hasher) HashEmpty(nonce []byte, index []byte, level uint32) []byte {
	return ch.Digest(
		[]byte{emptyIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
	)
}
