package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
	"github.com/coniks-sys/libmerkleprefixtree-go/kv"
)

func NewMerkleTreeFromKV(db kv.DB, epoch uint64) (*MerkleTree, error) {
	nonceKey := append([]byte(TreeNonceIdentifier), util.ULongToBytes(epoch)...)
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
	return m, nil
}

func (m *MerkleTree) reconstructTree(db kv.DB, parent MerkleNode, epoch uint64, prefixBits []bool) (MerkleNode, error) {
	n, err := loadNode(db, epoch, prefixBits)
	if err != nil {
		return nil, err
	}
	n.setParent(parent)
	if _, ok := n.(*emptyNode); ok {
		return n, nil
	}
	if _, ok := n.(*userLeafNode); ok {
		return n, nil
	}
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
		n.setParent(parent)
		switch n.(type) {
		case *userLeafNode, *emptyNode:
			break loadingLoop
		}
		parent = n
	}

	return m, nil
}

func (m *MerkleTree) StoreToKV(epoch uint64, wb kv.Batch) {
	// store tree nodes
	m.root.storeToKV(epoch, []bool{}, wb)
	// store tree nonce
	wb.Put(append([]byte(TreeNonceIdentifier), util.ULongToBytes(epoch)...), m.nonce)
}
