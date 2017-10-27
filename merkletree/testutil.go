package merkletree

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
)

var keyPrefix = "key"
var valuePrefix = []byte("value")

// StaticPAD returns a pad with a static initial STR for _tests_.
func StaticPAD(t *testing.T, ad AssocData) *PAD {
	pad, err := NewPAD(ad, crypto.StaticSigning(t), crypto.StaticVRF(t), 10)
	if err != nil {
		t.Fatal(err)
	}
	str := NewSTR(pad.signKey, pad.ad, staticTree(t), 0, []byte{})
	pad.latestSTR = str
	pad.snapshots[0] = pad.latestSTR
	return pad
}

func staticTree(t *testing.T) *MerkleTree {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	m.nonce = []byte{}
	return m
}

func newTestTree(t *testing.T) *MerkleTree {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
