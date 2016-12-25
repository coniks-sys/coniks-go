package merkletreekv

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

// StoreSTR stores str into the db under the key
// which is the combination of the STRIdentifier
// and the str's Epoch.
func StoreSTR(db kv.DB, str *merkletree.SignedTreeRoot) error {
	wb := db.NewBatch()
	buff := new(bytes.Buffer)
	if err := merkletree.EncodeSTR(buff, str); err != nil {
		return err
	}

	wb.Put(strKey(str.Epoch), buff.Bytes())
	return db.Write(wb)
}

// LoadSTR loads the STR corresponding to the specified epoch.
func LoadSTR(db kv.DB, epoch uint64) (*merkletree.SignedTreeRoot, error) {
	bbuff, err := db.Get(strKey(epoch))
	if err != nil {
		return nil, err
	}
	buff := bytes.NewBuffer(bbuff)
	return merkletree.DecodeSTR(buff)
}

func strKey(epoch uint64) []byte {
	key := make([]byte, 0, 1+8)
	key = append(key, STRIdentifier)
	key = append(key, utils.ULongToBytes(epoch)...)
	return key
}
