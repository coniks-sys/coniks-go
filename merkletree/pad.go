package merkletree

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/storage/kv"
)

var (
	ErrorSTRNotFound    = errors.New("[merkletree] STR not found")
	ErrorNilPolicies    = errors.New("[merkletree] Nil policies")
	ErrorBadEpochLength = errors.New("[merkletree] Bad epoch length")
)

// PAD is an acronym for persistent authenticated dictionary
type PAD struct {
	key          crypto.SigningKey
	tree         *MerkleTree // will be used to create the next STR
	snapshots    map[uint64]*SignedTreeRoot
	loadedEpochs []uint64 // slice of epochs in snapshots
	latestSTR    *SignedTreeRoot
	policies     Policies // the current policies in place
	db           kv.DB
}

// NewPAD creates new PAD consisting of an array of hash chain
// indexed by the epoch and its maximum length is length
func NewPAD(policies Policies, db kv.DB, key crypto.SigningKey, length uint64) (*PAD, error) {
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
	pad.db = db
	pad.policies = policies
	pad.snapshots = make(map[uint64]*SignedTreeRoot, length)
	pad.loadedEpochs = make([]uint64, 0, length)
	pad.updateInternal(nil, 0)
	return pad, nil
}

// if policies is nil, the previous policies will be used
func (pad *PAD) signTreeRoot(m *MerkleTree, epoch uint64) {
	var prevStrHash []byte
	if pad.latestSTR == nil {
		prevStrHash = make([]byte, crypto.HashSizeByte)
		if _, err := rand.Read(prevStrHash); err != nil {
			// panic here since if there is an error, it will break the PAD.
			panic(err)
		}
	} else {
		prevStrHash = crypto.Digest(pad.latestSTR.sig)
	}
	pad.latestSTR = NewSTR(pad.key, pad.policies, m, epoch, prevStrHash)
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
		vrfKeyChanged := 1 != (subtle.ConstantTimeCompare(
			pad.policies.vrfPrivate()[:],
			policies.vrfPrivate()[:]))
		pad.policies = policies
		if vrfKeyChanged {
			pad.reshuffle()
		}
	}

	pad.StoreToKV(epoch)
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

	pad.updateInternal(policies, pad.latestSTR.epoch+1)
}

func (pad *PAD) Set(key string, value []byte) error {
	index, _ := pad.computePrivateIndex(key, pad.policies.vrfPrivate())
	return pad.tree.Set(index, key, value)
}

func (pad *PAD) Lookup(key string) (*AuthenticationPath, error) {
	return pad.LookupInEpoch(key, pad.latestSTR.epoch)
}

func (pad *PAD) LookupInEpoch(key string, epoch uint64) (*AuthenticationPath, error) {
	str := pad.GetSTR(epoch)
	if str == nil {
		return nil, ErrorSTRNotFound
	}
	lookupIndex, proof := pad.computePrivateIndex(key, str.policies.vrfPrivate())
	ap := str.tree.Get(lookupIndex)
	ap.vrfProof = proof
	return ap, nil
}

func (pad *PAD) GetSTR(epoch uint64) *SignedTreeRoot {
	if epoch >= pad.latestSTR.epoch {
		return pad.latestSTR
	}
	if pad.snapshots[epoch] != nil {
		return pad.snapshots[epoch]
	}
	// look through persistent storage
	// str := new(SignedTreeRoot)
	// err := str.LoadFromKV(pad.db, pad.key, epoch)
	// if err != nil {
	// return nil
	// }
	// return str
	return nil // util we have a better way to construct the tree partially based on the lookup index.
}

func (pad *PAD) TB(key string, value []byte) (*TemporaryBinding, error) {
	str := pad.latestSTR
	index, _ := pad.computePrivateIndex(key, pad.policies.vrfPrivate())
	tb := str.sig
	tb = append(tb, index...)
	tb = append(tb, value...)
	sig := crypto.Sign(pad.key, tb)

	err := pad.tree.Set(index, key, value)

	return &TemporaryBinding{
		index: index,
		value: value,
		sig:   sig,
	}, err
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

func (pad *PAD) computePrivateIndex(key string,
	vrfPrivKey *[vrf.SecretKeySize]byte) (index, proof []byte) {
	index, proof = vrf.Prove([]byte(key), vrfPrivKey)
	return
}
