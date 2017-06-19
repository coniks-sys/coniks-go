package merkletree

import (
	"bytes"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/hasher"
	conikshasher "github.com/coniks-sys/coniks-go/crypto/hasher/coniks"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	// ErrBindingsDiffer indicates that the value included in the proof
	// is different from the expected value.
	ErrBindingsDiffer = errors.New("[merkletree] The values included in the bindings are different")
	// ErrUnverifiableCommitment indicates that the leaf node's commitment is unverifiable.
	ErrUnverifiableCommitment = errors.New("[merkletree] Could not verify the commitment")
	// ErrIndicesMismatch indicates that there is a mismatch
	// between the lookup index and the leaf index.
	ErrIndicesMismatch = errors.New("[merkletree] The lookup index is inconsistent with the index of the proof node")
	// ErrUnequalTreeHashes indicates that the hash computed from the authentication path
	// and the hash taken from the signed tree root are different.
	ErrUnequalTreeHashes = errors.New("[merkletree] The hashes computed from the authentication path and the STR are unequal")
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
		return conikshasher.New().HashEmpty(
			treeNonce,
			n.Index,
			n.Level,
		)
	} else {
		return conikshasher.New().HashLeaf(
			treeNonce,
			n.Index,
			n.Level,
			n.Commitment.Value,
		)
	}
}

// A ProofType indicates whether an AuthenticationPath is
// a proof of inclusion or a proof of absence.
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
	PrunedTree  []hasher.Hash
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
			hash = conikshasher.New().Digest(ap.PrunedTree[depth][:], hash)
		} else {
			hash = conikshasher.New().Digest(hash, ap.PrunedTree[depth][:])
		}
	}
	return hash
}

// Verify first compares the lookup index with the leaf index.
// It expects the lookup index and the leaf index match in the
// first l bits with l is the Level of the proof node if ap is
// a proof of absence. It also verifies the value and
// the commitment (in case of the proof of inclusion).
// Finally, it recomputes the tree's root node from ap,
// and compares it to treeHash, which is taken from a STR.
// Specifically, treeHash has to come from the STR whose tree returns ap.
//
// This should be called after the VRF index is verified successfully.
func (ap *AuthenticationPath) Verify(key, value, treeHash []byte) error {
	if ap.ProofType() == ProofOfAbsence {
		// Check if i and j match in the first l bits
		indexBits := utils.ToBits(ap.Leaf.Index)
		lookupIndexBits := utils.ToBits(ap.LookupIndex)
		for i := 0; i < int(ap.Leaf.Level); i++ {
			if indexBits[i] != lookupIndexBits[i] {
				return ErrIndicesMismatch
			}
		}
		// expect the value is nil since we suppressed
		// the salt & value (see Get())
		if ap.Leaf.Value != nil {
			return ErrBindingsDiffer
		}
	} else {
		// Verify the key-value binding returned in the ProofNode
		if !bytes.Equal(ap.Leaf.Value, value) {
			return ErrBindingsDiffer
		}
		if !ap.Leaf.Commitment.Verify(key, value) {
			return ErrUnverifiableCommitment
		}
	}

	if !bytes.Equal(treeHash, ap.authPathHash()) {
		return ErrUnequalTreeHashes
	}
	return nil
}

// ProofType returns the type of ap. It does a comparison
// between the leaf index and the lookup index to determine
// the proof type, and sets ap's proof type the first time this
// method called, memoizing the proof type for subsequent calls.
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
