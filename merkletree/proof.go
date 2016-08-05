package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type AuthenticationPath struct {
	TreeNonce   []byte
	PrunedTree  [][crypto.HashSizeByte]byte
	LookupIndex []byte
	VrfProof    []byte
	Leaf        ProofNode
}

type ProofNode interface {
	Level() int
	Index() []byte
	Value() []byte
	IsEmpty() bool
	Commitment() []byte
}

func computeLeafHash(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel int, isLeafEmpty bool) (leafHash []byte) {
	if isLeafEmpty {
		// empty leaf node
		leafHash = crypto.Digest(
			[]byte{EmptyBranchIdentifier},      // K_empty
			[]byte(ap.TreeNonce),               // K_n
			[]byte(leafIndex),                  // i
			[]byte(util.IntToBytes(leafLevel)), // l
		)
	} else {
		// user leaf node
		leafHash = crypto.Digest(
			[]byte{LeafIdentifier},             // K_leaf
			[]byte(ap.TreeNonce),               // K_n
			[]byte(leafIndex),                  // i
			[]byte(util.IntToBytes(leafLevel)), // l
			[]byte(leafCommitment),             // commit(key|| value)
		)
	}
	return
}

func authPathHash(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel int, isLeafEmpty bool) []byte {
	hash := computeLeafHash(ap, leafIndex, leafCommitment, leafLevel, isLeafEmpty)
	depth := leafLevel - 1
	indexBits := util.ToBits(leafIndex)
	for depth > -1 {
		if indexBits[depth] { // right child
			hash = crypto.Digest(ap.PrunedTree[depth][:], hash)
		} else {
			hash = crypto.Digest(hash, ap.PrunedTree[depth][:])
		}
		depth -= 1
	}
	return hash
}

// VerifyAuthPath should be called after the vrf index is verified successfully
func VerifyAuthPath(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel int, isLeafEmpty bool,
	treeHash []byte) bool {
	// step 1. Verify if it's a proof of inclusion/proof of absence
	if !bytes.Equal(leafIndex, ap.LookupIndex) {
		// proof of absence
		// Check if i and j match in the first l bits
		indexBits := util.ToBits(leafIndex)
		lookupIndexBits := util.ToBits(ap.LookupIndex)

		for i := 0; i < leafLevel; i++ {
			if indexBits[i] != lookupIndexBits[i] {
				return false
			}
		}
	}

	// step 2. Verify the auth path of the returned leaf
	hash := authPathHash(ap, leafIndex, leafCommitment, leafLevel, isLeafEmpty)
	if !bytes.Equal(treeHash, hash) {
		return false
	}
	return true
}

var _ ProofNode = (*userLeafNode)(nil)
var _ ProofNode = (*emptyNode)(nil)

func (n *emptyNode) Level() int {
	return n.level
}

func (n *emptyNode) Index() []byte {
	return n.index
}

func (n *emptyNode) Value() []byte {
	return nil
}

func (n *emptyNode) IsEmpty() bool {
	return true
}

func (n *emptyNode) Commitment() []byte {
	return nil
}

func (n *userLeafNode) Level() int {
	return n.level
}

func (n *userLeafNode) Index() []byte {
	return n.index
}

func (n *userLeafNode) Value() []byte {
	return n.value
}

func (n *userLeafNode) IsEmpty() bool {
	return false
}

func (n *userLeafNode) Commitment() []byte {
	return n.commitment
}
