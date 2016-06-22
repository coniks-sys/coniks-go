package merkletree

import (
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
)

var (
	ErrorSTRNotFound = errors.New("[merkletree] STR not found")
	ErrorNilPolicies = errors.New("[merkletree] Nil policies")
)

// PAD is an acronym for persistent authenticated dictionary
type PAD struct {
	key          crypto.SigningKey
	tree         *MerkleTree
	snapshots    map[uint64]*SignedTreeRoot
	loadedEpochs []uint64 // slice of counters in snapshots
	currentSTR   *SignedTreeRoot
}

// NewPAD creates new PAD consisting of an array of hash chain
// indexed by the counter and its maximum length is len
func NewPAD(policies Policies, key crypto.SigningKey, len int64) (*PAD, error) {
	if policies == nil {
		panic(ErrorNilPolicies)
	}
	var err error
	pad := new(PAD)
	pad.key = key
	pad.tree, err = NewMerkleTree()
	if err != nil {
		return nil, err
	}
	pad.snapshots = make(map[uint64]*SignedTreeRoot, len)
	pad.loadedEpochs = make([]uint64, 0, len)
	pad.updateInternal(policies, 1)
	return pad, nil
}

// if policies is nil, the previous policies will be used
func (pad *PAD) generateNextSTR(policies Policies, m *MerkleTree, counter uint64) {
	var prevStrHash []byte
	if pad.currentSTR == nil {
		prevStrHash = make([]byte, crypto.HashSizeByte)
	} else {
		prevStrHash = crypto.Digest(pad.currentSTR.serialize())
		if policies == nil {
			policies = pad.currentSTR.policies
		}
	}
	pad.currentSTR = NewSTR(pad.key, policies, m, counter, prevStrHash)
}

func (pad *PAD) updateInternal(policies Policies, counter uint64) {
	pad.tree.recomputeHash()
	m := pad.tree.Clone()
	pad.generateNextSTR(policies, m, counter)
	pad.snapshots[counter] = pad.currentSTR
	pad.loadedEpochs = append(pad.loadedEpochs, counter)
}

func (pad *PAD) Update(policies Policies) error {
	// delete older str(s) as needed
	if len(pad.loadedEpochs) == cap(pad.loadedEpochs) {
		n := cap(pad.loadedEpochs) / 2
		for i := 0; i < n; i++ {
			delete(pad.snapshots, pad.loadedEpochs[i])
		}
		pad.loadedEpochs = append(pad.loadedEpochs[:0], pad.loadedEpochs[n:]...)
	}

	pad.updateInternal(policies, pad.currentSTR.counter+1)
	return nil
}

func (pad *PAD) Set(key string, value []byte) error {
	return pad.tree.Set(key, value)
}

func (pad *PAD) LookUp(key string) (MerkleNode, *AuthenticationPath) {
	str := pad.currentSTR
	return str.tree.Get(key)
}

func (pad *PAD) LookUpInEpoch(key string, counter uint64) (MerkleNode, *AuthenticationPath, error) {
	str := pad.GetSTR(counter)
	if str == nil {
		return nil, nil, ErrorSTRNotFound
	}
	n, ap := str.tree.Get(key)
	return n, ap, nil
}

func (pad *PAD) GetSTR(counter uint64) *SignedTreeRoot {
	switch true {
	case counter >= pad.currentSTR.counter:
		return pad.currentSTR
	case counter < 1:
		return nil
	default:
		return pad.snapshots[counter]
	}
}