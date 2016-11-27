package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

// ProofNode can be a user node or an empty node,
// which is included in the returned AuthenticationPath
// of a given index. The type of that node can be determined
// by the IsEmpty value. It also provides an opening of
// the commitment if the returned AuthenticationPath
// is a proof of inclusion.
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
			[]byte{EmptyBranchIdentifier},        // K_empty
			[]byte(treeNonce),                    // K_n
			[]byte(n.Index),                      // i
			[]byte(utils.UInt32ToBytes(n.Level)), // l
		)
	} else {
		// user leaf node
		return crypto.Digest(
			[]byte{LeafIdentifier},               // K_leaf
			[]byte(treeNonce),                    // K_n
			[]byte(n.Index),                      // i
			[]byte(utils.UInt32ToBytes(n.Level)), // l
			[]byte(n.Commitment.Value),           // commit(key|| value)
		)
	}
}

type ProofType int

const (
	undeterminedProof ProofType = iota
	ProofOfAbsence
	ProofOfInclusion
)

// AuthenticationPath is a pruned tree containing
// the prefix path between the corresponding leaf node
// (of type ProofNode) and the root. This is a proof
// of inclusion or absence of requested index.
// A proof of inclusion is when the leaf index
// equals the lookup index.
type AuthenticationPath struct {
	TreeNonce   []byte
	PrunedTree  [][crypto.HashSizeByte]byte
	LookupIndex []byte
	VrfProof    []byte
	Leaf        *ProofNode
	proofType   ProofType
}

func (ap *AuthenticationPath) authPathHash() []byte {
	hash := ap.Leaf.hash(ap.TreeNonce)
	indexBits := utils.ToBits(ap.Leaf.Index)
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

// VerifyBinding verifies both the value and the commitment
// of the proof node of the authentication path.
//
// This should be called only when ap is a proof of inclusion.
func (ap *AuthenticationPath) VerifyBinding(key, value []byte) bool {
	return bytes.Equal(ap.Leaf.Value, value) &&
		ap.Leaf.Commitment.Verify(key, value)
}

// VerifyIndex checks if the private index of the proof node and
// the lookup index match in the first l bits with l is the Level
// of the proof node.
//
// This should be called only when ap is a proof of absence.
func (ap *AuthenticationPath) VerifyIndex() bool {
	// Check if i and j match in the first l bits
	indexBits := utils.ToBits(ap.Leaf.Index)
	lookupIndexBits := utils.ToBits(ap.LookupIndex)
	for i := 0; i < int(ap.Leaf.Level); i++ {
		if indexBits[i] != lookupIndexBits[i] {
			return false
		}
	}
	return true
}

// VerifySTR recomputes the tree's root node from the authentication path,
// and compares it to treeHash, which is taken from a STR.
// Specifically, treeHash has to come from the STR whose tree returns
// the authentication path.
func (ap *AuthenticationPath) VerifySTR(treeHash []byte) bool {
	return bytes.Equal(treeHash, ap.authPathHash())
}

// Verify combines VerifyBinding(), VerifyIndex(), and VerifySTR(),
// and abstracts away the detail of the failure.
// This should be called after the VRF index is verified successfully.
func (ap *AuthenticationPath) Verify(key, value, treeHash []byte) bool {
	switch {
	case ap.ProofType() == ProofOfAbsence && ap.VerifyIndex(),
		ap.ProofType() == ProofOfInclusion && ap.VerifyBinding(key, value):
		return ap.VerifySTR(treeHash)
	default:
		return false
	}
}

func (ap *AuthenticationPath) ProofType() ProofType {
	if ap.proofType == undeterminedProof {
		if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
			ap.proofType = ProofOfInclusion
		} else {
			ap.proofType = ProofOfAbsence
		}
	}
	return ap.proofType
}
