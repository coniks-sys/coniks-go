package merkletree

import (
	"bytes"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	conikshasher "github.com/coniks-sys/coniks-go/crypto/hasher/coniks"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

var (
	// ErrSTRNotFound indicates that the STR has been evicted from
	// memory, because the maximum number of cached PAD snapshots
	// has been exceeded.
	ErrSTRNotFound = errors.New("[merkletree] STR not found")
)

// A PAD represents a persistent authenticated dictionary,
// and includes the underlying MerkleTree, cached snapshots,
// the latest SignedTreeRoot, two key pairs for signing and VRF
// computation, and additional developer-specified AssocData.
type PAD struct {
	signKey      sign.PrivateKey
	vrfKey       vrf.PrivateKey
	tree         *MerkleTree // will be used to create the next STR
	snapshots    map[uint64]*SignedTreeRoot
	loadedEpochs []uint64 // slice of epochs in snapshots
	latestSTR    *SignedTreeRoot
	ad           AssocData
}

// NewPAD creates new PAD with the given associated data ad,
// signing key pair signKey, VRF key pair vrfKey, and the
// maximum capacity for the snapshot cache len.
func NewPAD(ad AssocData, signKey sign.PrivateKey, vrfKey vrf.PrivateKey, len uint64) (*PAD, error) {
	if ad == nil {
		panic("[merkletree] PAD must be created with non-nil associated data")
	}
	var err error
	pad := new(PAD)
	pad.signKey = signKey
	pad.vrfKey = vrfKey
	pad.tree, err = NewMerkleTree()
	if err != nil {
		return nil, err
	}
	pad.ad = ad
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
			// panic here since if there is an error, it
			// will break the PAD.
			panic(err)
		}
	} else {
		prevHash = conikshasher.New().Digest(pad.latestSTR.Signature)
	}
	pad.tree.recomputeHash()
	m := pad.tree.Clone()
	pad.latestSTR = NewSTR(pad.signKey, pad.ad, m, epoch, prevHash)
}

func (pad *PAD) updateInternal(ad AssocData, epoch uint64) {
	// Create STR with the `ad` that was used in the prev. Set()
	// operation.
	pad.signTreeRoot(epoch)
	pad.snapshots[epoch] = pad.latestSTR
	pad.loadedEpochs = append(pad.loadedEpochs, epoch)
	if ad != nil { // update the `ad` if necessary
		pad.ad = ad
	}
}

// Update generates a new snapshot of the tree.
// It should be called at the beginning of each epoch.
// Specifically, it extends the hash chain by issuing
// a new signed tree root. It may remove some older signed tree roots from
// memory if the cached PAD snapshots exceeded the maximum capacity.
// ad should be nil if the PAD's associated data ad do not change.
func (pad *PAD) Update(ad AssocData) {
	// delete older str(s) as needed
	if len(pad.loadedEpochs) == cap(pad.loadedEpochs) {
		n := cap(pad.loadedEpochs) / 2
		for i := 0; i < n; i++ {
			delete(pad.snapshots, pad.loadedEpochs[i])
		}
		pad.loadedEpochs = append(pad.loadedEpochs[:0], pad.loadedEpochs[n:]...)
	}
	pad.updateInternal(ad, pad.latestSTR.Epoch+1)
}

// Set computes the private index for the given key using
// the current VRF private key to create a new index-to-value binding,
// and inserts it into the PAD's underlying Merkle tree. This ensures
// the index-to-value binding will be included in the next PAD snapshot.
func (pad *PAD) Set(key string, value []byte) error {
	return pad.tree.Set(pad.Index(key), key, value)
}

// Lookup searches the requested key in the latest snapshot of the PAD,
// and returns the corresponding AuthenticationPath proving inclusion
// or absence of the requested key.
func (pad *PAD) Lookup(key string) (*AuthenticationPath, error) {
	return pad.LookupInEpoch(key, pad.latestSTR.Epoch)
}

// LookupInEpoch searches the requested key in the snapshot at the
// requested epoch.
// It returns ErrorSTRNotFound if the signed tree root of the requested epoch
// has been removed from memory, indicating to the server that the
// STR for the requested epoch should be retrieved from persistent storage.
func (pad *PAD) LookupInEpoch(key string, epoch uint64) (*AuthenticationPath, error) {
	str := pad.GetSTR(epoch)
	if str == nil {
		return nil, ErrSTRNotFound
	}
	// TODO: If the vrf key is rotated, we'd need to use the key
	// corresponding to the `epoch` here.  See #120
	lookupIndex, proof := pad.computePrivateIndex(key, pad.vrfKey)
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
// the private index for the requested key.
func (pad *PAD) Index(key string) []byte {
	index, _ := pad.computePrivateIndex(key, pad.vrfKey)
	return index
}

// reshuffle recomputes indices of keys and store them with their values
// in new tree with new new position; swaps pad.tree if everything worked
// out. If there is any error on the way (lack of entropy for randomness)
// reshuffle will panic
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

func (pad *PAD) computePrivateIndex(key string, vrfKey vrf.PrivateKey) (index, proof []byte) {
	index, proof = vrfKey.Prove([]byte(key))
	return
}
