package merkletreekv

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/storage/kv"
)

// StorePAD stores pad to the db.
// StorePAD uses the same key to store the PAD, so the old PAD
// would be replaced by the newly stored PAD.
func StorePAD(db kv.DB, pad *merkletree.PAD) error {
	wb := db.NewBatch()
	buff := new(bytes.Buffer)
	if err := merkletree.EncodePAD(buff, pad); err != nil {
		return err
	}
	wb.Put([]byte{PADIdentifier}, buff.Bytes())
	return db.Write(wb)
}

// LoadPAD reconstructs the PAD stored in the db.
// It requires the caller pass the maximum capacity
// for the snapshot cache length.
func LoadPAD(db kv.DB, length uint64) (*merkletree.PAD, error) {
	bbuff, err := db.Get([]byte{PADIdentifier})
	if err != nil {
		return nil, err
	}
	buff := bytes.NewBuffer(bbuff)
	return merkletree.DecodePAD(length, buff)
}
