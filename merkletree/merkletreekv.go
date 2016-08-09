package merkletree

import (
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	ErrorBadTreeNonce = errors.New("[merkletree] Bad tree nonce")
)

func NewMerkleTreeFromKV(db kv.DB, epoch uint64) (*MerkleTree, error) {
	nonceKey := append([]byte{TreeNonceIdentifier}, util.ULongToBytes(epoch)...)
	val, err := db.Get(nonceKey)
	var nonce []byte
	if err != nil {
		return nil, err
	} else if len(val) != crypto.HashSizeByte {
		return nil, ErrorBadTreeNonce
	} else {
		nonce = val
	}
	m := new(MerkleTree)
	m.nonce = nonce
	root, err := m.reconstructTree(db, nil, epoch, []bool{})
	if err != nil {
		return nil, err
	}
	m.root = root.(*interiorNode)
	m.hash = m.root.Hash(m)
	return m, nil
}

func (m *MerkleTree) reconstructTree(db kv.DB, parent MerkleNode, epoch uint64, prefixBits []bool) (MerkleNode, error) {
	n, err := loadNode(db, epoch, prefixBits)
	if err != nil {
		return nil, err
	}

	if _, ok := n.(*emptyNode); ok {
		n.(*emptyNode).parent = parent
		return n, nil
	}
	if _, ok := n.(*userLeafNode); ok {
		n.(*userLeafNode).parent = parent
		return n, nil
	}
	n.(*interiorNode).parent = parent
	n.(*interiorNode).leftChild, err = m.reconstructTree(db, n, epoch, append(prefixBits, false))
	if err != nil {
		return nil, err
	}
	n.(*interiorNode).rightChild, err = m.reconstructTree(db, n, epoch, append(prefixBits, true))
	if err != nil {
		return nil, err
	}
	return n, nil
}

func ReconstructBranch(db kv.DB, epoch uint64, index []byte) (*MerkleTree, error) {
	indexBits := util.ToBits(index)
	m := new(MerkleTree)
	root, err := loadNode(db, epoch, []bool{})
	if err != nil {
		return nil, err
	}
	m.root = root.(*interiorNode)
	var parent = root
loadingLoop:
	for depth := 1; depth < len(indexBits); depth++ {
		n, err := loadNode(db, epoch, indexBits[:depth])
		if err != nil {
			return nil, err
		}
		if indexBits[depth-1] {
			parent.(*interiorNode).rightChild = n
		} else {
			parent.(*interiorNode).leftChild = n
		}
		switch n.(type) {
		case *userLeafNode:
			n.(*userLeafNode).parent = parent
			break loadingLoop
		case *emptyNode:
			n.(*emptyNode).parent = parent
			break loadingLoop
		case *interiorNode:
			n.(*interiorNode).parent = parent
		}
		parent = n
	}

	return m, nil
}

func (m *MerkleTree) StoreToKV(epoch uint64, wb kv.Batch) {
	// store tree nodes
	m.root.storeToKV(epoch, []bool{}, wb)
	// store tree nonce
	wb.Put(append([]byte{TreeNonceIdentifier}, util.ULongToBytes(epoch)...), m.nonce)
}
