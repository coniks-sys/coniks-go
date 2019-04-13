package merkletree

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
)

var keyPrefix = "key"
var valuePrefix = []byte("value")

var staticSigningKey = crypto.NewStaticTestSigningKey()
var staticVRFKey = crypto.NewStaticTestVRFKey()

// StaticPAD returns a pad with a static initial STR for _tests_.
func StaticPAD(t *testing.T, ad AssocData) *PAD {
	pad, err := NewPAD(ad, staticSigningKey, staticVRFKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	str := NewSTR(pad.signKey, pad.ad, StaticTree(t), 0, []byte{})
	pad.latestSTR = str
	pad.snapshots[0] = pad.latestSTR
	return pad
}

// StaticTree returns an empty tree with empty nonce for _tests_.
func StaticTree(t *testing.T) *MerkleTree {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	m.nonce = []byte{}
	m.recomputeHash()
	return m
}

func newEmptyTreeForTest(t *testing.T) *MerkleTree {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	return m
}
