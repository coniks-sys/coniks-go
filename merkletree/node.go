package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type node struct {
	parent MerkleNode
	level  uint32
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
	salt       []byte
	index      []byte
	commitment []byte
}

type emptyNode struct {
	node
	index []byte
}

func NewInteriorNode(parent MerkleNode, level uint32, prefixBits []bool) *interiorNode {
	prefixLeft := append([]bool(nil), prefixBits...)
	prefixLeft = append(prefixLeft, false)
	prefixRight := append([]bool(nil), prefixBits...)
	prefixRight = append(prefixRight, true)
	leftBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: util.ToBytes(prefixLeft),
	}

	rightBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: util.ToBytes(prefixRight),
	}
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  level,
		},
		leftChild:  leftBranch,
		rightChild: rightBranch,
		leftHash:   nil,
		rightHash:  nil,
	}
	leftBranch.parent = newNode
	rightBranch.parent = newNode

	return newNode
}

type MerkleNode interface {
	isEmpty() bool
	Hash(*MerkleTree) []byte
	Clone(*interiorNode) MerkleNode
}

var _ MerkleNode = (*userLeafNode)(nil)
var _ MerkleNode = (*interiorNode)(nil)
var _ MerkleNode = (*emptyNode)(nil)

func (n *interiorNode) Hash(m *MerkleTree) []byte {
	if n.leftHash == nil {
		n.leftHash = n.leftChild.Hash(m)
	}
	if n.rightHash == nil {
		n.rightHash = n.rightChild.Hash(m)
	}
	return crypto.Digest(n.leftHash, n.rightHash)
}

func (n *userLeafNode) Hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{LeafIdentifier},              // K_leaf
		[]byte(m.nonce),                     // K_n
		[]byte(n.index),                     // i
		[]byte(util.UInt32ToBytes(n.level)), // l
		[]byte(n.commitment),                // commit(key|| value)
	)
}

func (n *emptyNode) Hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{EmptyBranchIdentifier},       // K_empty
		[]byte(m.nonce),                     // K_n
		[]byte(n.index),                     // i
		[]byte(util.UInt32ToBytes(n.level)), // l
	)
}

func (n *interiorNode) Clone(parent *interiorNode) MerkleNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		leftHash:  append([]byte{}, n.leftHash...),
		rightHash: append([]byte{}, n.rightHash...),
	}
	if n.leftChild == nil ||
		n.rightChild == nil {
		panic(ErrorInvalidTree)
	}
	newNode.leftChild = n.leftChild.Clone(newNode)
	newNode.rightChild = n.rightChild.Clone(newNode)
	return newNode
}

func (n *userLeafNode) Clone(parent *interiorNode) MerkleNode {
	return &userLeafNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		key:        n.key,
		value:      n.value,
		salt:       n.salt,
		index:      append([]byte{}, n.index...), // make a copy of index
		commitment: n.commitment,
	}
}

func (n *emptyNode) Clone(parent *interiorNode) MerkleNode {
	return &emptyNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		index: append([]byte{}, n.index...), // make a copy of index
	}
}

func (n *userLeafNode) isEmpty() bool {
	return false
}

func (n *interiorNode) isEmpty() bool {
	return false
}

func (n *emptyNode) isEmpty() bool {
	return true
}
