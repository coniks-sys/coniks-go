package merkletree

import (
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	ErrorBadEpoch = errors.New("[merkletree] Bad STR Epoch. STR's epoch must be nonzero")
)

// SignedTreeRoot represents a signed tree root, which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous epochs, the hash of the
// previous STR, and its signature.
// STR should be final
type SignedTreeRoot struct {
	tree        *MerkleTree
	epoch       uint64
	prevEpoch   uint64
	prevStrHash []byte
	sig         []byte
	policies    Policies
}

func NewSTR(key crypto.SigningKey, policies Policies, m *MerkleTree, epoch uint64, prevHash []byte) *SignedTreeRoot {
	if epoch < 0 {
		panic(ErrorBadEpoch)
	}
	prevEpoch := epoch - 1
	if epoch == 0 {
		prevEpoch = 0
	}
	str := &SignedTreeRoot{
		tree:        m,
		epoch:       epoch,
		prevEpoch:   prevEpoch,
		prevStrHash: prevHash,
		policies:    policies,
	}
	bytesPreSig := str.Serialize()
	str.sig = crypto.Sign(key, bytesPreSig)
	return str
}

// Serialize encodes the STR to a byte array with the following format:
// [epoch, previous epoch, tree hash, previous STR hash, policies serialization]
func (str *SignedTreeRoot) Serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, util.ULongToBytes(str.epoch)...) // t - epoch number
	if str.epoch > 0 {
		strBytes = append(strBytes, util.ULongToBytes(str.prevEpoch)...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, str.tree.hash...)            // root
	strBytes = append(strBytes, str.prevStrHash...)          // previous STR hash
	strBytes = append(strBytes, str.policies.Serialize()...) // P
	return strBytes
}

func (str *SignedTreeRoot) Root() []byte {
	return str.tree.hash
}

func (str *SignedTreeRoot) Epoch() uint64 {
	return str.epoch
}

func (str *SignedTreeRoot) PreviousEpoch() uint64 {
	return str.prevEpoch
}

func (str *SignedTreeRoot) PreviousSTRHash() []byte {
	return str.prevStrHash
}

func (str *SignedTreeRoot) Signature() []byte {
	return str.sig
}
