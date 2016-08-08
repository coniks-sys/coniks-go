package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
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
// [epoch, prevEpoch, prevStrHash, Signature]
func (str *SignedTreeRoot) StoreToKV(wb kv.Batch) {
	buf := make([]byte, 0, 8+8+crypto.HashSizeByte+sign.SignatureSize)
	buf = append(buf, util.ULongToBytes(str.Epoch)...)
	if str.Epoch > 0 {
		buf = append(buf, util.ULongToBytes(str.PreviousEpoch)...)
	}
	buf = append(buf, str.PreviousSTRHash...)
	buf = append(buf, str.Signature...)
	wb.Put(str.serializeKVKey(str.Epoch), buf)

	str.tree.StoreToKV(str.Epoch, wb)
	str.Policies.StoreToKV(str.Epoch, wb)
}

func (str *SignedTreeRoot) LoadFromKV(db kv.DB, key sign.PrivateKey, epoch uint64) error {
	buf, err := db.Get(str.serializeKVKey(epoch))
	if err != nil {
		return err
	}
	str.Epoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
	buf = buf[8:]
	if str.Epoch > 0 {
		str.PreviousEpoch = uint64(binary.LittleEndian.Uint64(buf[:8]))
		buf = buf[8:]
	}
	str.PreviousSTRHash = buf[:crypto.HashSizeByte]
	buf = buf[crypto.HashSizeByte:]
	str.Signature = buf[:sign.SignatureSize]
	buf = buf[sign.SignatureSize:]
	if len(buf) != 0 {
		panic(kv.ErrorBadBufferLength)
	}

	return nil
}
