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
	tree            *MerkleTree
	Epoch           uint64
	PreviousEpoch   uint64
	PreviousSTRHash []byte
	Signature       []byte
	Policies        Policies
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
		tree:            m,
		Epoch:           epoch,
		PreviousEpoch:   prevEpoch,
		PreviousSTRHash: prevHash,
		Policies:        policies,
	}
	bytesPreSig := str.Serialize()
	str.Signature = crypto.Sign(key, bytesPreSig)
	return str
}

// Serialize encodes the STR to a byte array with the following format:
// [epoch, previous epoch, tree hash, previous STR hash, policies serialization]
func (str *SignedTreeRoot) Serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, util.ULongToBytes(str.Epoch)...) // t - epoch number
	if str.Epoch > 0 {
		strBytes = append(strBytes, util.ULongToBytes(str.PreviousEpoch)...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, str.tree.hash...)            // root
	strBytes = append(strBytes, str.PreviousSTRHash...)      // previous STR hash
	strBytes = append(strBytes, str.Policies.Serialize()...) // P
	return strBytes
}

func (str *SignedTreeRoot) Root() []byte {
	return str.tree.hash
}
