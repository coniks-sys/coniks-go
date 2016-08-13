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
	Leaf        *ProofNode
}

type ProofNode struct {
	Level      uint32
	Salt       []byte
	Index      []byte
	Value      []byte
	IsEmpty    bool
	Commitment []byte
}

func computeLeafHash(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel uint32, isLeafEmpty bool) (leafHash []byte) {
	if isLeafEmpty {
		// empty leaf node
		leafHash = crypto.Digest(
			[]byte{EmptyBranchIdentifier},         // K_empty
			[]byte(ap.TreeNonce),                  // K_n
			[]byte(leafIndex),                     // i
			[]byte(util.UInt32ToBytes(leafLevel)), // l
		)
	} else {
		// user leaf node
		leafHash = crypto.Digest(
			[]byte{LeafIdentifier},                // K_leaf
			[]byte(ap.TreeNonce),                  // K_n
			[]byte(leafIndex),                     // i
			[]byte(util.UInt32ToBytes(leafLevel)), // l
			[]byte(leafCommitment),                // commit(key|| value)
		)
	}
	return
}

func authPathHash(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel uint32, isLeafEmpty bool) []byte {
	hash := computeLeafHash(ap, leafIndex, leafCommitment, leafLevel, isLeafEmpty)
	indexBits := util.ToBits(leafIndex)
	depth := leafLevel
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

// VerifyAuthPath should be called after the vrf index is verified successfully
func VerifyAuthPath(ap *AuthenticationPath,
	leafIndex, leafCommitment []byte, leafLevel uint32, isLeafEmpty bool,
	treeHash []byte) bool {
	// step 1. Verify if it's a proof of inclusion/proof of absence
	if !bytes.Equal(leafIndex, ap.LookupIndex) {
		// proof of absence
		// Check if i and j match in the first l bits
		indexBits := util.ToBits(leafIndex)
		lookupIndexBits := util.ToBits(ap.LookupIndex)

		for i := 0; i < int(leafLevel); i++ {
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

func VerifyCommitment(salt []byte, key string, value []byte, commitment []byte) bool {
	got := crypto.Digest(salt, []byte(key), value)
	return bytes.Equal(got, commitment)
}
