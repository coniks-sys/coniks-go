package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

// SignedTreeRoot represents a signed tree root, which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous epochs, the hash of the
// previous STR, and its signature.
// STR should be final
type SignedTreeRoot struct {
	treeRoot    *interiorNode
	epoch       int64
	prevEpoch   int64
	prevStrHash []byte
	sig         []byte
	policies    []byte
	prev        *SignedTreeRoot
	key         crypto.KeyPair
}

func newSTR(m *MerkleTree, ep, prevEp int64, prevHash []byte,
	key crypto.KeyPair) *SignedTreeRoot {
	bytesPreSig := getSTRBytesForSig(m, ep, prevEp, prevHash)
	sig := crypto.Sign(key, bytesPreSig)

	return &SignedTreeRoot{
		treeRoot:    m.root,
		epoch:       ep,
		prevEpoch:   prevEp,
		prevStrHash: prevHash,
		sig:         sig,
		policies:    m.policies.Serialize(),
		prev:        nil,
		key:         key,
	}
}

func (cur *SignedTreeRoot) generateNextSTR(m *MerkleTree, ep int64) *SignedTreeRoot {
	prevEpoch := cur.epoch
	prevStrHash := crypto.Digest(serializeSTR(*cur))

	nextStr := newSTR(m, ep, prevEpoch, prevStrHash, cur.key)
	nextStr.prev = cur
	return nextStr
}

func getSTRBytesForSig(m *MerkleTree, ep int64, prevEp int64, prevHash []byte) []byte {
	var strBytes []byte

	strBytes = append(strBytes, util.LongToBytes(ep)...)     // t - epoch number
	strBytes = append(strBytes, util.LongToBytes(prevEp)...) // t_prev - previous epoch number
	strBytes = append(strBytes, m.root.serialize()...)       // root
	strBytes = append(strBytes, prevHash...)                 // previous STR hash
	strBytes = append(strBytes, m.policies.Serialize()...)   // P
	return strBytes
}

func serializeSTR(str SignedTreeRoot) []byte {
	var strBytes []byte

	strBytes = append(strBytes, str.treeRoot.serialize()...)        // root
	strBytes = append(strBytes, util.LongToBytes(str.epoch)...)     // epoch
	strBytes = append(strBytes, util.LongToBytes(str.prevEpoch)...) // previous epoch
	strBytes = append(strBytes, str.prevStrHash...)                 // previous hash
	strBytes = append(strBytes, str.sig...)                         // signature

	return strBytes
}
