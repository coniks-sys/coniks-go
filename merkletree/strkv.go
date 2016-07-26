package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func serializeSTRKVKey(epoch uint64) []byte {
	buf := make([]byte, 0, 1+8)
	buf = append(buf, STRIdentifier)
	buf = append(buf, util.ULongToBytes(epoch)...)
	return buf
}

func (str *SignedTreeRoot) StoreToKV(wb kv.Batch) {
	buf := make([]byte, 0, 8+8+2*crypto.HashSizeByte)
	buf = append(buf, str.tree.hash...)
	buf = append(buf, util.ULongToBytes(str.epoch)...)
	buf = append(buf, util.ULongToBytes(str.prevEpoch)...)
	buf = append(buf, str.prevStrHash...)
	wb.Put(serializeSTRKVKey(str.epoch), buf)

	str.tree.StoreToKV(str.epoch, wb)
	str.policies.StoreToKV(str.epoch, wb)
}

// TODO: change to str.LoadFromKV
func loadSTR(db kv.DB, epoch uint64) (*SignedTreeRoot, error) {
	tree, err := NewMerkleTreeFromKV(db, epoch)
	if err != nil {
		return nil, err
	}
	str := new(SignedTreeRoot)
	buf, err := db.Get(serializeSTRKVKey(epoch))
	if err == db.ErrNotFound() {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	str.tree = tree
	str.epoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
	buf = buf[8:]
	str.prevEpoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
	buf = buf[8:]
	str.prevStrHash = buf[:crypto.HashSizeByte]
	buf = buf[crypto.HashSizeByte:]

	// return deserializeNode(nodeBytes), nil
	return str, nil
}
