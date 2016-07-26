package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

// NewPADFromKV creates new PAD with a latest tree stored in the KV db
func NewPADFromKV(policies Policies, db kv.DB, key crypto.SigningKey, length int64) (*PAD, error) {
	if policies == nil {
		panic(ErrorNilPolicies)
	}
	var err error
	pad := new(PAD)
	pad.key = key
	// get latest epoch from db
	epBytes, err := db.Get([]byte(EpochIdentifier))
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
	pad.snapshots = make(map[uint64]*SignedTreeRoot, length)
	pad.loadedEpochs = make([]uint64, 0, length)
	pad.db = db
	pad.updateInternal(policies, ep)
	return pad, nil
}

func (pad *PAD) StoreToKV(epoch uint64) error {
	if pad.db == nil {
		return nil
	}
	wb := pad.db.NewBatch()
	pad.tree.StoreToKV(epoch, wb)
	pad.currentSTR.StoreToKV(wb)
	// and store latest STR's epoch to db
	wb.Put([]byte(EpochIdentifier), util.ULongToBytes(epoch))
	err := pad.db.Write(wb)
	if err != nil {
		return err
	}
	return nil
}
