package merkletree

import (
	"bytes"
	"crypto/subtle"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

var (
	// ErrorSTRNotFound indicates that the STR has been evicted from memory,
	// because the maximum number of cached PAD snapshots has been exceeded.
	ErrorSTRNotFound = errors.New("[merkletree] STR not found")
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
// indexed by the epoch and its maximum length is len.
func NewPAD(policies *Policies, signKey sign.PrivateKey, len uint64) (*PAD, error) {
	if policies == nil {
		panic("[merkletree] PAD must be created with a non-NULL Policies struct")
	}
	var err error
	pad := new(PAD)
	pad.signKey = signKey
	pad.tree, err = NewMerkleTree()
	if err != nil {
		return nil, err
	}
	pad.policies = *policies
	pad.snapshots = make(map[uint64]*SignedTreeRoot, len)
	pad.loadedEpochs = make([]uint64, 0, len)
	pad.updateInternal(nil, 0)
	return pad, nil
}

func (pad *PAD) signTreeRoot(epoch uint64) {
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
	pad.tree.recomputeHash()
	m := pad.tree.Clone()
	pad.latestSTR = NewSTR(pad.signKey, pad.policies, m, epoch, prevHash)
}

func (pad *PAD) updateInternal(policies *Policies, epoch uint64) {
	// create STR with the policies that were actually used in the prev.
	// Set() operation
	pad.signTreeRoot(epoch)
	pad.snapshots[epoch] = pad.latestSTR
	pad.loadedEpochs = append(pad.loadedEpochs, epoch)
	if policies != nil { // update the policies if necessary
		vrfKeyChanged := 1 != subtle.ConstantTimeCompare(
			pad.policies.vrfPrivateKey,
			policies.vrfPrivateKey)
		pad.policies = *policies
		if vrfKeyChanged {
			pad.reshuffle()
		}
	}
}

// Update generates a new snapshot of the tree.
// It should be called in the beginning of each epoch.
// Specifically, it extends the hash chain by issuing
// a new signed tree root. It may remove some older signed tree roots from
// memory if the cached PAD snapshots exceeded the maximum capacity.
// policies could be nil if the PAD's policies do not change.
// If the VRF private key is changed (by passing a new Policies),
// the underlying tree would be reshuffled. It also means
// the private index of all new key-to-value bindings
// will be computed using the new VRF private key.
func (pad *PAD) Update(policies *Policies) {
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

// Set computes the private index of the given key using
// the current VRF private key (which will be inserted in the next
// signed tree root) to create a new index-to-key binding,
// and then Set inserts it into the Merkle tree underlying the PAD.
func (pad *PAD) Set(key string, value []byte) error {
	return pad.tree.Set(pad.Index(key), key, value)
}

// Lookup searches the requested key in the latest snapshot of the PAD.
func (pad *PAD) Lookup(key string) (*AuthenticationPath, error) {
	return pad.LookupInEpoch(key, pad.latestSTR.Epoch)
}

// LookupInEpoch searches the requested key in the snapshot at the requested epoch.
// It returns ErrorSTRNotFound if the signed tree root of the requested epoch
// has been removed from memory.
func (pad *PAD) LookupInEpoch(key string, epoch uint64) (*AuthenticationPath, error) {
	str := pad.GetSTR(epoch)
	if str == nil {
		return nil, ErrorSTRNotFound
	}
	lookupIndex, proof := pad.computePrivateIndex(key, str.Policies.vrfPrivateKey)
	ap := str.tree.Get(lookupIndex)
	ap.VrfProof = proof
	return ap, nil
}

// GetSTR returns the signed tree root of the requested epoch.
// This signed tree root is read from the cached snapshots of the PAD.
// It returns nil if the signed tree root has been removed from the memory.
func (pad *PAD) GetSTR(epoch uint64) *SignedTreeRoot {
	if epoch >= pad.latestSTR.Epoch {
		return pad.latestSTR
	}
	return pad.snapshots[epoch]
}

// LatestSTR returns the latest signed tree root of the PAD.
func (pad *PAD) LatestSTR() *SignedTreeRoot {
	return pad.latestSTR
}

// Sign uses the _current_ signing key underlying the PAD to sign msg.
func (pad *PAD) Sign(msg ...[]byte) []byte {
	return pad.signKey.Sign(bytes.Join(msg, nil))
}

// Index uses the _current_ VRF private key of the PAD to compute
// the private index of the requested key.
func (pad *PAD) Index(key string) []byte {
	index, _ := pad.computePrivateIndex(key, pad.policies.vrfPrivateKey)
	return index
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
		if err := newTree.Set(pad.Index(n.key), n.key, n.value); err != nil {
			panic(err)
		}
	})
	pad.tree = newTree
}

func (pad *PAD) computePrivateIndex(key string,
	vrfPrivKey vrf.PrivateKey) (index, proof []byte) {
	index, proof = vrfPrivKey.Prove([]byte(key))
	return
}
