package merkletree

import (
	"bytes"

	"encoding/json"
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

// AssocData is associated data to be hashed into the STR.
type AssocData interface {
	Serialize() []byte
}

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
	Ad              AssocData
}

// FIXME this shouldn't really be here; find a more elegant way to deal with
// the AssocData interface or (at least) move to a another file:
type FIXMEPolicies struct { // can't use protocol.Policies: otherwise import cycle!
	Version       string
	HashID        string
	VrfPublicKey  vrf.PublicKey
	EpochDeadline uint64
}

func (p *FIXMEPolicies) Serialize() []byte {
	return nil
}
func (str *SignedTreeRoot) UnmarshalJSON(m []byte) error {
	type Str struct {
		tree            *MerkleTree
		TreeHash        []byte
		Epoch           uint64
		PreviousEpoch   uint64
		PreviousSTRHash []byte
		Signature       []byte
		Ad              json.RawMessage
	}
	hStr := &Str{}
	if err := json.Unmarshal(m, hStr); err != nil {
		return err
	}
	// AssocData
	p := &FIXMEPolicies{}
	if err := json.Unmarshal([]byte(hStr.Ad), p); err != nil {
		return err
	}
	str.Ad = p

	str.tree = hStr.tree
	str.TreeHash = hStr.TreeHash
	str.Epoch = hStr.Epoch
	str.PreviousEpoch = hStr.PreviousEpoch
	str.PreviousSTRHash = hStr.PreviousSTRHash
	str.Signature = hStr.Signature

	return nil
}

// END of FIXME

func NewSTR(key sign.PrivateKey, ad AssocData, m *MerkleTree, epoch uint64, prevHash []byte) *SignedTreeRoot {
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
		Ad:              ad,
	}
	bytesPreSig := str.Serialize()
	str.Signature = key.Sign(bytesPreSig)
	return str
}

// Serialize serializes the signed tree root into
// a specified format for signing.
func (str *SignedTreeRoot) Serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, utils.ULongToBytes(str.Epoch)...) // t - epoch number
	if str.Epoch > 0 {
		strBytes = append(strBytes, utils.ULongToBytes(str.PreviousEpoch)...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, str.TreeHash...)        // root
	strBytes = append(strBytes, str.PreviousSTRHash...) // previous STR hash
	strBytes = append(strBytes, str.Ad.Serialize()...)
	return strBytes
}

// VerifyHashChain computes the hash of savedSTR's signature,
// and compares it to the hash of previous STR included
// in the issued STR. The hash chain is valid if
// these two hash values are equal and consecutive.
func (str *SignedTreeRoot) VerifyHashChain(savedSTR *SignedTreeRoot) bool {
	hash := crypto.Digest(savedSTR.Signature)
	return str.PreviousEpoch == savedSTR.Epoch &&
		str.Epoch == savedSTR.Epoch+1 &&
		bytes.Equal(hash, str.PreviousSTRHash)
}
