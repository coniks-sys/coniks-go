// TODO(huyvq): Remove package import.
// Other package shouldn't need to import this package,
// instead they should insert `hasher` and import this
// package using a blank import name.
// Should be adressed in #06.

package coniks

import (
	"crypto"

	"github.com/coniks-sys/coniks-go/crypto/hasher"
	"github.com/coniks-sys/coniks-go/utils"
)

func init() {
	hasher.RegisterHasher(CONIKSHasher, New)
}

const (
	// CONIKSHasher is the identity of the hashing algorithm
	// specified in the CONIKSHasher paper.
	CONIKSHasher = "CONIKS Hasher"

	emptyIdentifier = 'E'
	leafIdentifier  = 'L'
)

type coniksHasher struct {
	crypto.Hash
}

// New returns an instance of CONIKS hasher.
func New() hasher.PADHasher {
	return &coniksHasher{Hash: crypto.SHA512_256}
}

func (ch *coniksHasher) Digest(ms ...[]byte) []byte {
	h := ch.New()
	for _, m := range ms {
		h.Write(m)
	}
	return h.Sum(nil)
}

func (coniksHasher) ID() string {
	return CONIKSHasher
}

func (ch *coniksHasher) Size() int {
	return ch.Size()
}

func (ch *coniksHasher) HashInterior(left, right []byte) []byte {
	return ch.Digest(left, right)
}

func (ch *coniksHasher) HashLeaf(nonce []byte, index []byte, level uint32, commit []byte) []byte {
	return ch.Digest(
		[]byte{leafIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
		commit,
	)
}

func (ch *coniksHasher) HashEmpty(nonce []byte, index []byte, level uint32) []byte {
	return ch.Digest(
		[]byte{emptyIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
	)
}
