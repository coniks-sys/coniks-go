package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func (str *SignedTreeRoot) serializeKVKey(epoch uint64) []byte {
	buf := make([]byte, 0, 1+8)
	buf = append(buf, STRIdentifier)
	buf = append(buf, util.ULongToBytes(epoch)...)
	return buf
}

// StoreToKV stores a STR into db as following scheme:
// [epoch, prevEpoch, prevStrHash]
func (str *SignedTreeRoot) StoreToKV(wb kv.Batch) {
	buf := make([]byte, 0, 8+8+crypto.HashSizeByte)
	buf = append(buf, util.ULongToBytes(str.epoch)...)
	if str.epoch > 0 {
		buf = append(buf, util.ULongToBytes(str.prevEpoch)...)
	}
	buf = append(buf, str.prevStrHash...)
	wb.Put(str.serializeKVKey(str.epoch), buf)

	str.tree.StoreToKV(str.epoch, wb)
	str.policies.StoreToKV(str.epoch, wb)
}

func (str *SignedTreeRoot) LoadFromKV(db kv.DB, policies Policies, key crypto.SigningKey, epoch uint64) error {
	err := policies.LoadFromKV(db, epoch)
	if err != nil {
		return err
	}
	str.policies = policies
	tree, err := NewMerkleTreeFromKV(db, epoch)
	if err != nil {
		return err
	}
	str.tree = tree

	buf, err := db.Get(str.serializeKVKey(epoch))
	if err == db.ErrNotFound() {
		return nil
	} else if err != nil {
		return err
	}
	str.epoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
	buf = buf[8:]
	if str.epoch > 0 {
		str.prevEpoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
		buf = buf[8:]
	}
	str.prevStrHash = buf[:crypto.HashSizeByte]
	buf = buf[crypto.HashSizeByte:]
	if len(buf) != 0 {
		panic(kv.ErrorBadBufferLength)
	}
	bytesPreSig := str.Serialize()
	str.sig = crypto.Sign(key, bytesPreSig)

	return nil
}
