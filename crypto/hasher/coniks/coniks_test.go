package coniks

import (
	"encoding/hex"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/hasher"
)

// h2h converts a hex string into its Hash object.
func h2h(h string) hasher.Hash {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("invalid hex string")
	}
	var ret hasher.Hash
	copy(ret[:], b)
	return ret
}

// s2h converts a byte slice into its Hash object.
func s2h(s []byte) hasher.Hash {
	var ret hasher.Hash
	copy(ret[:], s)
	return ret
}

func TestHashLeafVectors(t *testing.T) {
	for _, tc := range []struct {
		treeNonce [32]byte // treeNonce is treeID in KT, it should be a 32-byte array for cross-project compatibility
		index     []byte
		depth     uint32
		leaf      []byte
		want      hasher.Hash
	}{
		{treeNonce: [32]byte{0}, index: []byte("foo"), depth: 128, leaf: []byte("leaf"), want: h2h("65e7f29787a6168affd016656bb1f4f03af91cf7416270f5015005f8594d3eb6")},
	} {
		if got, want := s2h(New().HashLeaf(tc.treeNonce[:], tc.index, tc.depth, tc.leaf)), tc.want; got != want {
			t.Errorf("HashLeaf(%v, %s, %v, %s): %x, want %x", tc.treeNonce, tc.index, tc.depth, tc.leaf, got, want)
		}
	}
}

func TestHashEmptyVectors(t *testing.T) {
	for _, tc := range []struct {
		treeNonce [32]byte // treeNonce is treeID in KT, it should be a 32-byte array for cross-project compatibility
		index     []byte
		depth     uint32
		want      hasher.Hash
	}{
		{treeNonce: [32]byte{0}, index: []byte("foo"), depth: 128, want: h2h("1a6b0eb739b32a46e7d679a9be03f522e907f53423aacb82e550bf657d1afb10")},
	} {
		if got, want := s2h(New().HashEmpty(tc.treeNonce[:], tc.index, tc.depth)), tc.want; got != want {
			t.Errorf("HashLeaf(%v, %s, %v): %x, want %x", tc.treeNonce, tc.index, tc.depth, got, want)
		}
	}
}
