package merkletree

import (
	"encoding/gob"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type node struct {
	parent merkleNode
}

type interiorNode struct {
	node
	Level      uint32
	leftChild  merkleNode
	rightChild merkleNode
	LeftHash   []byte
	RightHash  []byte
}

type userLeafNode struct {
	node
	Level      uint32
	Key        string
	Value      []byte
	Index      []byte
	Commitment *crypto.Commit
}

type emptyNode struct {
	node
	Level uint32
	Index []byte
}

func newInteriorNode(parent merkleNode, level uint32, prefixBits []bool) *interiorNode {
	prefixLeft := append([]bool(nil), prefixBits...)
	prefixLeft = append(prefixLeft, false)
	prefixRight := append([]bool(nil), prefixBits...)
	prefixRight = append(prefixRight, true)
	leftBranch := &emptyNode{
		Level: level + 1,
		Index: utils.ToBytes(prefixLeft),
	}

	rightBranch := &emptyNode{
		Level: level + 1,
		Index: utils.ToBytes(prefixRight),
	}
	newNode := &interiorNode{
		node: node{
			parent: parent,
		},
		Level:      level,
		leftChild:  leftBranch,
		rightChild: rightBranch,
		LeftHash:   nil,
		RightHash:  nil,
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
	if n.LeftHash == nil {
		n.LeftHash = n.leftChild.hash(m)
	}
	if n.RightHash == nil {
		n.RightHash = n.rightChild.hash(m)
	}
	return crypto.Digest(n.LeftHash, n.RightHash)
}

func (n *userLeafNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{LeafIdentifier},               // K_leaf
		[]byte(m.nonce),                      // K_n
		[]byte(n.Index),                      // i
		[]byte(utils.UInt32ToBytes(n.Level)), // l
		[]byte(n.Commitment.Value),           // commit(key|| value)
	)
}

func (n *emptyNode) hash(m *MerkleTree) []byte {
	return crypto.Digest(
		[]byte{EmptyBranchIdentifier},        // K_empty
		[]byte(m.nonce),                      // K_n
		[]byte(n.Index),                      // i
		[]byte(utils.UInt32ToBytes(n.Level)), // l
	)
}

func (n *interiorNode) clone(parent *interiorNode) merkleNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
		},
		Level:     n.Level,
		LeftHash:  append([]byte{}, n.LeftHash...),
		RightHash: append([]byte{}, n.RightHash...),
	}
	if n.leftChild == nil ||
		n.rightChild == nil {
		panic(ErrInvalidTree)
	}
	newNode.leftChild = n.leftChild.clone(newNode)
	newNode.rightChild = n.rightChild.clone(newNode)
	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) merkleNode {
	return &userLeafNode{
		node: node{
			parent: parent,
		},
		Level:      n.Level,
		Key:        n.Key,
		Value:      n.Value,
		Index:      append([]byte{}, n.Index...), // make a copy of index
		Commitment: n.Commitment,
	}
}

func (n *emptyNode) clone(parent *interiorNode) merkleNode {
	return &emptyNode{
		node: node{
			parent: parent,
		},
		Level: n.Level,
		Index: append([]byte{}, n.Index...), // make a copy of index
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

// gob encoding/decoding

func init() {
	gob.Register(&interiorNode{})
	gob.Register(&userLeafNode{})
	gob.Register(&emptyNode{})
}

// encodeNode encodes a merkleNode n using the gob.Encoder enc.
// If n is an interior node, this also encodes n's children recursively.
func encodeNode(enc *gob.Encoder, n merkleNode) error {
	err := enc.Encode(&n)
	if err != nil {
		return err
	}
	if in, ok := n.(*interiorNode); ok {
		err = encodeNode(enc, in.leftChild)
		if err != nil {
			return err
		}
		err = encodeNode(enc, in.rightChild)
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeNode returns a merkleNode from the decoder.
func decodeNode(dec *gob.Decoder) (merkleNode, error) {
	var get merkleNode
	if err := dec.Decode(&get); err != nil {
		return nil, err
	}
	return get, nil
}
