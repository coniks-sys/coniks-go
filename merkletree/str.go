package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/utils"
)

// SignedTreeRoot represents a signed tree root, which is generated
// at the beginning of every epoch.
// Signed tree roots contain the current root node,
// the current and previous epochs, the hash of the
// previous STR, and its signature.
// STR should be final
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

func innerSTRSerialize(epochB, prevEpochB, root, prevStrHash, policiesB []byte) []byte {
	var strBytes []byte
	strBytes = append(strBytes, epochB...) // t - epoch number
	if prevEpochB != nil {
		strBytes = append(strBytes, prevEpochB...) // t_prev - previous epoch number
	}
	strBytes = append(strBytes, root...)        // root
	strBytes = append(strBytes, prevStrHash...) // previous STR hash
	strBytes = append(strBytes, policiesB...)   // P
	return strBytes
}

// Serialize encodes the STR to a byte array with the following format:
// [epoch, previous epoch, tree hash, previous STR hash, policies serialization]
func (str *SignedTreeRoot) Serialize() []byte {
	var prevEpochBytes []byte
	if str.Epoch > 0 {
		prevEpochBytes = util.ULongToBytes(str.PreviousEpoch)
	} else {
		prevEpochBytes = nil
	}
	return innerSTRSerialize(util.ULongToBytes(str.Epoch), prevEpochBytes, str.tree.hash, str.PreviousSTRHash, str.Policies.Serialize())
}

func (str *SignedTreeRoot) Root() []byte {
	return str.tree.hash
}

func VerifySTR(pk sign.PublicKey, epochB, prevEpochB, root, prevStrHash, policiesB, strSig []byte) bool {
	strBytes := innerSTRSerialize(epochB, prevEpochB, root, prevStrHash, policiesB)
	return pk.Verify(strBytes, strSig)
}

func VerifyHashChain(prevHash, savedSTRSig []byte) bool {
	hash := crypto.Digest(savedSTRSig)
	return bytes.Equal(hash, prevHash)
}
