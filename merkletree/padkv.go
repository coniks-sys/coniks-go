package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

// NewPADFromKV creates new PAD with a latest tree stored in the KV db
func NewPADFromKV(db kv.DB, policies Policies, key crypto.SigningKey, length int64) (*PAD, error) {
	var err error
	pad := new(PAD)
	pad.key = key
	pad.snapshots = make(map[uint64]*SignedTreeRoot, length)
	pad.loadedEpochs = make([]uint64, 0, length)
	pad.db = db

	// get latest epoch from db
	epBytes, err := db.Get([]byte{EpochIdentifier})
	if err != nil {
		return nil, err
	}
	if len(epBytes[:]) != 8 {
		panic(ErrorBadEpochLength)
	}
	ep := uint64(binary.LittleEndian.Uint64(epBytes[:8]))

	// reconstruct tree from db
	pad.tree, err = NewMerkleTreeFromKV(db, ep)
	if err != nil {
		return nil, err
	}

	// get str from db
	str := new(SignedTreeRoot)
	err = str.LoadFromKV(db, policies, key, ep)
	if err != nil {
		return nil, err
	}
	pad.latestSTR = str
	pad.policies = str.policies
	pad.snapshots[ep] = str
	pad.loadedEpochs = append(pad.loadedEpochs, ep)

	return pad, nil
}

func (pad *PAD) StoreToKV(epoch uint64) error {
	if pad.db == nil {
		return nil
	}
	wb := pad.db.NewBatch()
	pad.latestSTR.StoreToKV(wb)
	// and store latest STR's epoch to db
	wb.Put([]byte{EpochIdentifier}, util.ULongToBytes(epoch))
	err := pad.db.Write(wb)
	if err != nil {
		return err
	}
	return nil
}
