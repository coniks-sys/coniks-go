package merkletree

import (
	"crypto/subtle"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

var (
	ErrorSTRNotFound = errors.New("[merkletree] STR not found")
	ErrorNilPolicies = errors.New("[merkletree] Nil policies")
)

// PAD is an acronym for persistent authenticated dictionary
type PAD struct {
	signKey      sign.PrivateKey
	tree         *MerkleTree // will be used to create the next STR
	snapshots    map[uint64]*SignedTreeRoot
	loadedEpochs []uint64 // slice of epochs in snapshots
	latestSTR    *SignedTreeRoot
	policies     Policies // the current policies in place
}

// NewPAD creates new PAD consisting of an array of hash chain
// indexed by the epoch and its maximum length is len
func NewPAD(policies Policies, signKey sign.PrivateKey, len uint64) (*PAD, error) {
	if policies == nil {
		panic(ErrorNilPolicies)
	}
	var err error
	pad := new(PAD)
	pad.signKey = signKey
	pad.tree, err = NewMerkleTree()
	if err != nil {
		return nil, err
	}
	pad.policies = policies
	pad.snapshots = make(map[uint64]*SignedTreeRoot, len)
	pad.loadedEpochs = make([]uint64, 0, len)
	pad.updateInternal(nil, 0)
	return pad, nil
}

// if policies is nil, the previous policies will be used
func (pad *PAD) signTreeRoot(m *MerkleTree, epoch uint64) {
	var prevHash []byte
	if pad.latestSTR == nil {
		var err error
		prevHash, err = crypto.MakeRand()
		if err != nil {
			// panic here since if there is an error, it will break the PAD.
			panic(err)
		}
	} else {
		prevHash = crypto.Digest(pad.latestSTR.Signature)
	}
	pad.latestSTR = NewSTR(pad.signKey, pad.policies, m, epoch, prevHash)
}

func (pad *PAD) updateInternal(policies Policies, epoch uint64) {
	pad.tree.recomputeHash()
	m := pad.tree.Clone()
	// create STR with the policies that were actually used in the prev.
	// Set() operation
	pad.signTreeRoot(m, epoch)
	pad.snapshots[epoch] = pad.latestSTR
	pad.loadedEpochs = append(pad.loadedEpochs, epoch)

	if policies != nil { // update the policies if necessary
		vrfKeyChanged := 1 != subtle.ConstantTimeCompare(
			pad.policies.vrfPrivate(),
			policies.vrfPrivate())
		pad.policies = policies
		if vrfKeyChanged {
			pad.reshuffle()
		}
	}
}

func (pad *PAD) Update(policies Policies) {
	// delete older str(s) as needed
	if len(pad.loadedEpochs) == cap(pad.loadedEpochs) {
		n := cap(pad.loadedEpochs) / 2
		for i := 0; i < n; i++ {
			delete(pad.snapshots, pad.loadedEpochs[i])
		}
		pad.loadedEpochs = append(pad.loadedEpochs[:0], pad.loadedEpochs[n:]...)
	}

	pad.updateInternal(policies, pad.latestSTR.Epoch+1)
}

func (pad *PAD) Set(name string, value []byte) error {
	index, _ := pad.computePrivateIndex(name, pad.policies.vrfPrivate())
	return pad.tree.Set(index, name, value)
}

func (pad *PAD) Lookup(name string) (*AuthenticationPath, error) {
	return pad.LookupInEpoch(name, pad.latestSTR.Epoch)
}

func (pad *PAD) LookupInEpoch(name string, epoch uint64) (*AuthenticationPath, error) {
	str := pad.GetSTR(epoch)
	if str == nil {
		return nil, ErrorSTRNotFound
	}
	lookupIndex, proof := pad.computePrivateIndex(name, str.Policies.vrfPrivate())
	ap := str.tree.Get(lookupIndex)
	ap.VrfProof = proof
	return ap, nil
}

func (pad *PAD) GetSTR(epoch uint64) *SignedTreeRoot {
	if epoch >= pad.latestSTR.Epoch {
		return pad.latestSTR
	}
	return pad.snapshots[epoch]
}

func (pad *PAD) LatestSTR() *SignedTreeRoot {
	return pad.latestSTR
}

func (pad *PAD) TB(name string, value []byte) (*TemporaryBinding, error) {
	index, _ := pad.computePrivateIndex(name, pad.policies.vrfPrivate())
	tb := NewTB(pad.signKey, pad.latestSTR.Signature, index, value)
	err := pad.tree.Set(index, name, value)
	return tb, err
}

// reshuffle recomputes indices of keys and store them with their values in new
// tree with new new position;
// swaps pad.tree if everything worked out.
// if there is any error on the way (lack of entropy for randomness) reshuffle
// will panic
func (pad *PAD) reshuffle() {
	newTree, err := NewMerkleTree()
	if err != nil {
		panic(err)
	}
	pad.tree.visitLeafNodes(func(n *userLeafNode) {
		newIndex, _ := pad.computePrivateIndex(n.key, pad.policies.vrfPrivate())
		if err := newTree.Set(newIndex, n.key, n.value); err != nil {
			panic(err)
		}
	})
	pad.tree = newTree
}

func (pad *PAD) computePrivateIndex(name string,
	vrfPrivKey vrf.PrivateKey) (index, proof []byte) {
	index, proof = vrfPrivKey.Prove([]byte(name))
	return
}
