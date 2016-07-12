package merkletree

import (
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
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
	if epoch < 1 {
		panic(ErrorBadEpoch)
	}
	str := &SignedTreeRoot{
		tree:        m,
		epoch:       epoch,
		prevEpoch:   epoch - 1,
		prevStrHash: prevHash,
		policies:    policies,
	}
	bytesPreSig := str.getSTRBytesForSig()
	str.sig = crypto.Sign(key, bytesPreSig)
	return str
}

func (str *SignedTreeRoot) getSTRBytesForSig() []byte {
	var strBytes []byte
	strBytes = append(strBytes, util.ULongToBytes(str.epoch)...)     // t - epoch number
	strBytes = append(strBytes, util.ULongToBytes(str.prevEpoch)...) // t_prev - previous epoch number
	strBytes = append(strBytes, str.tree.hash...)                    // root
	strBytes = append(strBytes, str.prevStrHash...)                  // previous STR hash
	strBytes = append(strBytes, str.policies.Serialize()...)         // P
	return strBytes
}

func (str *SignedTreeRoot) serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, str.tree.hash...)                    // root
	strBytes = append(strBytes, util.ULongToBytes(str.epoch)...)     // epoch
	strBytes = append(strBytes, util.ULongToBytes(str.prevEpoch)...) // previous epoch
	strBytes = append(strBytes, str.prevStrHash...)                  // previous hash
	strBytes = append(strBytes, str.sig...)                          // signature
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
