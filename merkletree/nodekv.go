package merkletree

import (
	"encoding/binary"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func serializeKvKey(epoch uint64, prefixBits []bool) []byte {
	// NodeKeyIdentifier + epoch + len(prefixBits) + index
	index := util.ToBytes(prefixBits)
	key := make([]byte, 0, 1+8+4+len(index))
	key = append(key, NodeKeyIdentifier)
	key = append(key, util.ULongToBytes(epoch)...)
	key = append(key, util.IntToBytes(len(prefixBits))...)
	key = append(key, index...)
	return key
}

func (n *interiorNode) storeToKV(epoch uint64, prefixBits []bool, wb kv.Batch) {
	wb.Put(serializeKvKey(epoch, prefixBits), n.serialize())
	n.leftChild.storeToKV(epoch, append(prefixBits, false), wb)
	n.rightChild.storeToKV(epoch, append(prefixBits, true), wb)
}

func (n *userLeafNode) storeToKV(epoch uint64, prefixBits []bool, wb kv.Batch) {
	wb.Put(serializeKvKey(epoch, prefixBits), n.serialize())
}

func (n *emptyNode) storeToKV(epoch uint64, prefixBits []bool, wb kv.Batch) {
	wb.Put(serializeKvKey(epoch, prefixBits), n.serialize())
}

func (n *interiorNode) serialize() []byte {
	// identifier + level + leftHash + rightHash
	buf := make([]byte, 0, 1+4+crypto.HashSizeByte*2)
	buf = append(buf, InteriorNodeIdentifier)
	buf = append(buf, util.IntToBytes(n.level)...)
	buf = append(buf, n.leftHash...)
	buf = append(buf, n.rightHash...)
	return buf
}

func (n *userLeafNode) serialize() []byte {
	// identifier + level + len(key) + key + len(value) + value + salt + index + commitment
	buf := make([]byte, 0, 1+4+crypto.HashSizeByte*2+crypto.PrivateIndexSize+len(n.key)+len(n.value)+4+4)
	buf = append(buf, LeafIdentifier)
	buf = append(buf, util.IntToBytes(n.level)...)
	buf = append(buf, util.IntToBytes(len(n.key))...)
	buf = append(buf, []byte(n.key)...)
	buf = append(buf, util.IntToBytes(len(n.value))...)
	buf = append(buf, n.value...)
	buf = append(buf, n.salt...)
	buf = append(buf, n.index...)
	buf = append(buf, n.commitment...)
	return buf
}

func (n *emptyNode) serialize() []byte {
	// identifier + level + index
	buf := make([]byte, 0, 1+4+len(n.index))
	buf = append(buf, EmptyBranchIdentifier)
	buf = append(buf, util.IntToBytes(n.level)...)
	buf = append(buf, n.index...)
	return buf
}

func loadNode(db kv.DB, epoch uint64, prefixBits []bool) (MerkleNode, error) {
	nodeBytes, err := db.Get(serializeKvKey(epoch, prefixBits))
	if err == db.ErrNotFound() {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	return deserializeNode(nodeBytes), nil
}

func deserializeNode(buf []byte) MerkleNode {
	switch buf[0] {
	case InteriorNodeIdentifier:
		buf = buf[1:]
		n := new(interiorNode)
		n.level = int(binary.LittleEndian.Uint32(buf[:4]))
		buf = buf[4:]
		n.leftHash = append([]byte{}, buf[:crypto.HashSizeByte]...)
		buf = buf[crypto.HashSizeByte:]
		n.rightHash = append([]byte{}, buf[:crypto.HashSizeByte]...)
		buf = buf[crypto.HashSizeByte:]
		if len(buf) != 0 {
			panic(ErrorBadNodeLength)
		}
		return n
	case LeafIdentifier:
		buf = buf[1:]
		n := new(userLeafNode)
		n.level = int(binary.LittleEndian.Uint32(buf[:4]))
		buf = buf[4:]
		keyLen := int(binary.LittleEndian.Uint32(buf[:4]))
		buf = buf[4:]
		n.key = string(buf[:keyLen])
		buf = buf[keyLen:]
		valueLen := int(binary.LittleEndian.Uint32(buf[:4]))
		buf = buf[4:]
		n.value = buf[:valueLen]
		buf = buf[valueLen:]
		n.salt = buf[:crypto.HashSizeByte]
		buf = buf[crypto.HashSizeByte:]
		n.index = buf[:crypto.HashSizeByte]
		buf = buf[crypto.HashSizeByte:]
		n.commitment = buf[:crypto.HashSizeByte]
		buf = buf[crypto.HashSizeByte:]
		if len(buf) != 0 {
			panic(ErrorBadNodeLength)
		}
		return n
	case EmptyBranchIdentifier:
		buf = buf[1:]
		n := new(emptyNode)
		n.level = int(binary.LittleEndian.Uint32(buf[:4]))
		buf = buf[4:]
		n.index = buf[:]
		buf = buf[len(n.index):]
		if len(buf) != 0 {
			panic(ErrorBadNodeLength)
		}
		return n
	}
	panic(ErrorBadNodeIdentifier)
}
