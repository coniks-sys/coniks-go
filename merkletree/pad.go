package merkletree

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	ErrorSTRNotFound    = errors.New("[merkletree] STR not found")
	ErrorNilPolicies    = errors.New("[merkletree] Nil policies")
	ErrorBadEpochLength = errors.New("[merkletree] Bad epoch length")
)

// PAD is an acronym for persistent authenticated dictionary
type PAD struct {
	key          crypto.SigningKey
	tree         *MerkleTree
	snapshots    map[uint64]*SignedTreeRoot
	loadedEpochs []uint64 // slice of epochs in snapshots
	currentSTR   *SignedTreeRoot
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
	pad.snapshots = make(map[uint64]*SignedTreeRoot, length)
	pad.loadedEpochs = make([]uint64, 0, length)
	pad.db = db
	pad.updateInternal(policies, 0)
	return pad, nil
}

// NewPADFromDB creates new PAD with a latest tree stored in the db
func NewPADFromDB(policies Policies, db kv.DB, key crypto.SigningKey, length int64) (*PAD, error) {
	if policies == nil {
		panic(ErrorNilPolicies)
	}
	var err error
	pad := new(PAD)
	pad.key = key
	epBytes, err := db.Get([]byte(EpochIdentifier))
	if err != nil {
		return nil, err
	}
	if len(epBytes[:]) != 8 {
		panic(ErrorBadEpochLength)
	}
	ep := uint64(binary.LittleEndian.Uint64(epBytes[:8]))
	pad.tree, err = OpenMerkleTree(db, ep)
	if err != nil {
		return nil, err
	}
	pad.snapshots = make(map[uint64]*SignedTreeRoot, length)
	pad.loadedEpochs = make([]uint64, 0, length)
	pad.db = db
	pad.updateInternal(policies, 1)
	return pad, nil
}

// if policies is nil, the previous policies will be used
func (pad *PAD) generateNextSTR(policies Policies, m *MerkleTree, epoch uint64) {
	var prevStrHash []byte
	if pad.currentSTR == nil {
		prevStrHash = make([]byte, crypto.HashSizeByte)
		if _, err := rand.Read(prevStrHash); err != nil {
			// panic here since if there is an error, it will break the PAD.
			panic(err)
		}
	} else {
		prevStrHash = crypto.Digest(pad.currentSTR.sig)
		if policies == nil {
			policies = pad.currentSTR.policies
		}
	}
	pad.currentSTR = NewSTR(pad.key, policies, m, epoch, prevStrHash)
}

func (pad *PAD) updateInternal(policies Policies, epoch uint64) {
	pad.tree.recomputeHash()
	pad.Flush(epoch)
	m := pad.tree.Clone()
	pad.generateNextSTR(policies, m, epoch)
	pad.snapshots[epoch] = pad.currentSTR
	pad.loadedEpochs = append(pad.loadedEpochs, epoch)
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

	pad.updateInternal(policies, pad.currentSTR.epoch+1)
}

func (pad *PAD) Set(key string, value []byte) error {
	return pad.tree.Set(key, value)
}

func (pad *PAD) Lookup(key string) *AuthenticationPath {
	str := pad.currentSTR
	return str.tree.Get(key)
}

func (pad *PAD) LookupInEpoch(key string, epoch uint64) (*AuthenticationPath, error) {
	str := pad.GetSTR(epoch)
	if str == nil {
		return nil, ErrorSTRNotFound
	}
	ap := str.tree.Get(key)
	return ap, nil
}

func (pad *PAD) GetSTR(epoch uint64) *SignedTreeRoot {
	if epoch >= pad.currentSTR.epoch {
		return pad.currentSTR
	}
	return pad.snapshots[epoch]
}

func (pad *PAD) TB(key string, value []byte) (*TemporaryBinding, error) {
	//FIXME: compute private index twice
	//it would be refactored after merging VRF integration branch
	index := computePrivateIndex(key)
	tb := pad.currentSTR.sig
	tb = append(tb, index...)
	tb = append(tb, value...)
	sig := crypto.Sign(pad.key, tb)

	err := pad.Set(key, value)

	return &TemporaryBinding{
		index: index,
		value: value,
		sig:   sig,
	}, err
}

func (pad *PAD) Flush(epoch uint64) error {
	if pad.db == nil {
		return nil
	}
	wb := pad.db.NewBatch()
	pad.tree.Flush(epoch, wb)
	// and store latest STR's epoch to db
	wb.Put([]byte(EpochIdentifier), util.ULongToBytes(epoch))
	err := pad.db.Write(wb)
	if err != nil {
		return err
	}
	return nil
}
