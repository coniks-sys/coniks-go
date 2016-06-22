package merkletree

import (
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

var (
	ErrorBadCounter = errors.New("[merkletree] Bad STR Counter")
)

// SignedTreeRoot represents a signed tree root, which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous counters, the hash of the
// previous STR, and its signature.
// STR should be final
type SignedTreeRoot struct {
	tree        *MerkleTree
	counter     uint64
	prevCounter uint64
	prevStrHash []byte
	sig         []byte
	policies    Policies
}

func NewSTR(key crypto.SigningKey, policies Policies, m *MerkleTree, counter uint64, prevHash []byte) *SignedTreeRoot {
	if counter < 1 {
		panic(ErrorBadCounter)
	}
	str := &SignedTreeRoot{
		tree:        m,
		counter:     counter,
		prevCounter: counter - 1,
		prevStrHash: prevHash,
		policies:    policies,
	}
	bytesPreSig := str.getSTRBytesForSig()
	str.sig = crypto.Sign(key, bytesPreSig)
	return str
}

func (str *SignedTreeRoot) getSTRBytesForSig() []byte {
	var strBytes []byte
	strBytes = append(strBytes, util.ULongToBytes(str.counter)...)     // t - counter number
	strBytes = append(strBytes, util.ULongToBytes(str.prevCounter)...) // t_prev - previous counter number
	strBytes = append(strBytes, str.tree.hash...)                      // root
	strBytes = append(strBytes, str.prevStrHash...)                    // previous STR hash
	strBytes = append(strBytes, str.policies.Serialize()...)           // P
	return strBytes
}

func (str *SignedTreeRoot) serialize() []byte {
	var strBytes []byte
	strBytes = append(strBytes, str.tree.hash...)                      // root
	strBytes = append(strBytes, util.ULongToBytes(str.counter)...)     // counter
	strBytes = append(strBytes, util.ULongToBytes(str.prevCounter)...) // previous counter
	strBytes = append(strBytes, str.prevStrHash...)                    // previous hash
	strBytes = append(strBytes, str.sig...)                            // signature
	return strBytes
}

func (str *SignedTreeRoot) Root() []byte {
	return str.tree.hash
}

func (str *SignedTreeRoot) Counter() uint64 {
	return str.counter
}

func (str *SignedTreeRoot) PreviousCounter() uint64 {
	return str.prevCounter
}

func (str *SignedTreeRoot) PreviousSTRHash() []byte {
	return str.prevStrHash
}

func (str *SignedTreeRoot) Signature() []byte {
	return str.sig
}
