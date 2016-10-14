package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/utils"
)

// SignedTreeRoot represents a signed tree root (STR), which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous epochs, the hash of the
// previous STR, and its signature.
// The epoch number is a counter from 0, and increases by 1
// when a new signed tree root is issued by the PAD.
type SignedTreeRoot struct {
	tree            *MerkleTree
	TreeHash        []byte
	Epoch           uint64
	PreviousEpoch   uint64
	PreviousSTRHash []byte
	Signature       []byte
	Policies        Policies
}

func NewSTR(key sign.PrivateKey, policies Policies, m *MerkleTree, epoch uint64, prevHash []byte) *SignedTreeRoot {
	prevEpoch := epoch - 1
	if epoch == 0 {
		prevEpoch = 0
	}
	str := &SignedTreeRoot{
		tree:            m,
		TreeHash:        m.hash,
		Epoch:           epoch,
		PreviousEpoch:   prevEpoch,
		PreviousSTRHash: prevHash,
		Policies:        policies,
	}
	bytesPreSig := str.Serialize()
	str.Signature = key.Sign(bytesPreSig)
	return str
}

// Serialize serializes the signed tree root into
// the correct format for signing.
func (str *SignedTreeRoot) Serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, util.ULongToBytes(str.Epoch)...) // t - epoch number
	if str.Epoch > 0 {
		strBytes = append(strBytes, util.ULongToBytes(str.PreviousEpoch)...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, str.TreeHash...)             // root
	strBytes = append(strBytes, str.PreviousSTRHash...)      // previous STR hash
	strBytes = append(strBytes, str.Policies.Serialize()...) // P
	return strBytes
}

// VerifyHashChain computes the hash of savedSTR's signature,
// and compares it to the hash of previous STR included
// in the issued STR. The hash chain is valid if
// these two hash values are equal.
func (str *SignedTreeRoot) VerifyHashChain(savedSTR *SignedTreeRoot) bool {
	hash := crypto.Digest(savedSTR.Signature)
	return str.Epoch == savedSTR.Epoch+1 && bytes.Equal(hash, str.PreviousSTRHash)
}
