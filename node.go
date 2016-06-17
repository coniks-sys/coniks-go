package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

type node struct {
	parent MerkleNode
	level  int
}

type interiorNode struct {
	node
	leftChild  MerkleNode
	rightChild MerkleNode
	leftHash   []byte
	rightHash  []byte
}

type userLeafNode struct {
	node
	key        string
	value      []byte
	index      []byte
	commitment []byte
}

type emptyNode struct {
	node
}

type MerkleNode interface {
	Value() []byte
	isEmpty() bool
}

type LookUpProofNode interface {
	GetHash() []byte
}

var _ MerkleNode = (*userLeafNode)(nil)
var _ MerkleNode = (*interiorNode)(nil)
var _ MerkleNode = (*emptyNode)(nil)

func (node *userLeafNode) Value() []byte {
	return node.value
}

func (node *userLeafNode) isEmpty() bool {
	return false
}

func (node *interiorNode) Value() []byte {
	return nil
}

func (node *interiorNode) isEmpty() bool {
	return false
}

func (node *emptyNode) Value() []byte {
	return nil
}

func (node *emptyNode) isEmpty() bool {
	return true
}

var _ LookUpProofNode = (*node)(nil)

func (node *node) GetHash() []byte {
	parent, ok := node.parent.(*interiorNode)
	if !ok {
		return nil
	}
	switch parent.leftChild.(type) {
	case *emptyNode:
		if &parent.leftChild.(*emptyNode).node == node {
			return parent.leftHash
		}
	case *userLeafNode:
		if &parent.leftChild.(*userLeafNode).node == node {
			return parent.leftHash
		}
	default:
		return nil
	}

	return parent.rightHash
}

func (node *interiorNode) GetHash() []byte {
	return node.hash()
}

func (node *interiorNode) serialize() []byte {
	input := make([]byte, 0, len(node.leftHash)+len(node.rightHash))
	input = append(input, node.leftHash...)
	input = append(input, node.rightHash...)
	return input
}

func (node *interiorNode) hash() []byte {
	return crypto.Digest(node.serialize())
}

func (node *userLeafNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{LeafIdentifier},              // K_leaf
		[]byte(m.treeNonce),                 // K_n
		[]byte(node.index),                  // i
		[]byte(util.IntToBytes(node.level)), // l
		[]byte(node.commitment),             // commit(key|| value)
	)
}

func (node *emptyNode) hash(m *MerkleTree, prefixBits []bool) []byte {
	return crypto.Digest(
		[]byte{EmptyBranchIdentifier},            // K_empty
		[]byte(m.treeNonce),                      // K_n
		[]byte(util.ToBytes(prefixBits)),         // i
		[]byte(util.IntToBytes(len(prefixBits))), // l
	)
}

func (n *interiorNode) clone(parent *interiorNode) *interiorNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		leftHash:  n.leftHash,
		rightHash: n.rightHash,
	}

	if n.leftChild != nil {
		switch n.leftChild.(type) {
		case *interiorNode:
			newNode.leftChild = n.leftChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.leftChild = n.leftChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.leftChild = n.leftChild.(*emptyNode).clone(newNode)
		}
	}

	if n.rightChild != nil {
		switch n.rightChild.(type) {
		case *interiorNode:
			newNode.rightChild = n.rightChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.rightChild = n.rightChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.rightChild = n.rightChild.(*emptyNode).clone(newNode)
		}
	}

	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) *userLeafNode {
	newNode := &userLeafNode{
		key:        n.key,
		value:      n.value,
		index:      append([]byte{}, n.index...), // make a copy of index
		commitment: n.commitment,
	}
	newNode.parent = parent
	newNode.level = n.level

	return newNode
}

func (n *emptyNode) clone(parent *interiorNode) *emptyNode {
	newNode := &emptyNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
	}

	return newNode
}
