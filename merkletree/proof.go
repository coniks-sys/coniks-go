package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type ProofNode struct {
	Level      uint32
	Index      []byte
	Value      []byte
	IsEmpty    bool
	Commitment *crypto.Commit
}

func (n *ProofNode) hash(treeNonce []byte) []byte {
	if n.IsEmpty {
		// empty leaf node
		return crypto.Digest(
			[]byte{EmptyBranchIdentifier},       // K_empty
			[]byte(treeNonce),                   // K_n
			[]byte(n.Index),                     // i
			[]byte(util.UInt32ToBytes(n.Level)), // l
		)
	} else {
		// user leaf node
		return crypto.Digest(
			[]byte{LeafIdentifier},              // K_leaf
			[]byte(treeNonce),                   // K_n
			[]byte(n.Index),                     // i
			[]byte(util.UInt32ToBytes(n.Level)), // l
			[]byte(n.Commitment.Value),          // commit(key|| value)
		)
	}
}

type AuthenticationPath struct {
	TreeNonce   []byte
	PrunedTree  [][crypto.HashSizeByte]byte
	LookupIndex []byte
	VrfProof    []byte
	Leaf        *ProofNode
}

func (ap *AuthenticationPath) authPathHash() []byte {
	hash := ap.Leaf.hash(ap.TreeNonce)
	indexBits := util.ToBits(ap.Leaf.Index)
	depth := ap.Leaf.Level
	for depth > 0 {
		depth -= 1
		if indexBits[depth] { // right child
			hash = crypto.Digest(ap.PrunedTree[depth][:], hash)
		} else {
			hash = crypto.Digest(hash, ap.PrunedTree[depth][:])
		}
	}
	return hash
}

// Verify should be called after the vrf index is verified successfully
func (ap *AuthenticationPath) Verify(treeHash []byte) bool {
	// step 1. Verify if it's a proof of inclusion/proof of absence
	if !bytes.Equal(ap.Leaf.Index, ap.LookupIndex) {
		// proof of absence
		// Check if i and j match in the first l bits
		indexBits := util.ToBits(ap.Leaf.Index)
		lookupIndexBits := util.ToBits(ap.LookupIndex)
		for i := 0; i < int(ap.Leaf.Level); i++ {
			if indexBits[i] != lookupIndexBits[i] {
				return false
			}
		}
	}
	// step 2. Verify the auth path of the returned leaf
	if !bytes.Equal(treeHash, ap.authPathHash()) {
		return false
	}
	return true
}
