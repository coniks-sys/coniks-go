package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type node struct {
	parent merkleNode
	level  uint32
}

type interiorNode struct {
	node
	leftChild  merkleNode
	rightChild merkleNode
	leftHash   []byte
	rightHash  []byte
}

type userLeafNode struct {
	node
	key        string
	value      []byte
	index      []byte
	commitment *crypto.Commit
}

type emptyNode struct {
	node
	index []byte
}

func newInteriorNode(parent merkleNode, level uint32, prefixBits []bool) *interiorNode {
	prefixLeft := append([]bool(nil), prefixBits...)
	prefixLeft = append(prefixLeft, false)
	prefixRight := append([]bool(nil), prefixBits...)
	prefixRight = append(prefixRight, true)
	leftBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: utils.ToBytes(prefixLeft),
	}

	rightBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
		index: utils.ToBytes(prefixRight),
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

type merkleNode interface {
	isEmpty() bool
	hash(*MerkleTree) []byte
	clone(*interiorNode) merkleNode
}

var _ merkleNode = (*userLeafNode)(nil)
var _ merkleNode = (*interiorNode)(nil)
var _ merkleNode = (*emptyNode)(nil)

func (n *interiorNode) hash(m *MerkleTree) []byte {
	if n.leftHash == nil {
		n.leftHash = n.leftChild.hash(m)
	}
	if n.rightHash == nil {
		n.rightHash = n.rightChild.hash(m)
	}
	return crypto.Digest(n.leftHash, n.rightHash)
}

func (n *userLeafNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{LeafIdentifier},               // K_leaf
		[]byte(m.nonce),                      // K_n
		[]byte(n.index),                      // i
		[]byte(utils.UInt32ToBytes(n.level)), // l
		[]byte(n.commitment.Value),           // commit(key|| value)
	)
}

func (n *emptyNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{EmptyBranchIdentifier},        // K_empty
		[]byte(m.nonce),                      // K_n
		[]byte(n.index),                      // i
		[]byte(utils.UInt32ToBytes(n.level)), // l
	)
}

func (n *interiorNode) clone(parent *interiorNode) merkleNode {
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
	newNode.leftChild = n.leftChild.clone(newNode)
	newNode.rightChild = n.rightChild.clone(newNode)
	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) merkleNode {
	return &userLeafNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		key:        n.key,
		value:      n.value,
		index:      append([]byte{}, n.index...), // make a copy of index
		commitment: n.commitment,
	}
}

func (n *emptyNode) clone(parent *interiorNode) merkleNode {
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
