package merkletree

import (
	"errors"
	"hash"
)

var (
	ErrInvalidTree = errors.New("[merkletree] invalid tree")
)

const (
	EmptyBranchIdentifier = 'E'
	LeafIdentifier        = 'L'
)

type HashSuite struct {
	HashSizeByte int
	Hash         hash.Hash
}

type MerkleTree struct {
	hash      HashSuite
	treeNonce []byte
	salt      []byte
	root      *interiorNode
}

type interiorNode struct {
	parent     *interiorNode
	leftChild  interface{}
	rightChild interface{}
	leftHash   []byte
	rightHash  []byte
	level      int
}

type userLeafNode struct {
	interiorNode
	key   string
	value []byte
	index []byte
}

type MerkleNode interface {
	Value() []byte
}

func InitMerkleTree(treeNonce, salt []byte, hashFunc HashSuite) *MerkleTree {
	root := &interiorNode{
		parent:     nil,
		leftChild:  nil,
		rightChild: nil,
		leftHash:   nil,
		rightHash:  nil,
		level:      0,
	}

	m := &MerkleTree{
		treeNonce: treeNonce,
		salt:      salt,
		hash:      hashFunc,
		root:      root,
	}
	return m
}

func (m *MerkleTree) LookUp(key string) MerkleNode {
	lookupIndex := m.computePrivateIndex(key)
	position := 0
	var nodePointer interface{}
	nodePointer = m.root

	for nodePointer != nil {
		if _, ok := nodePointer.(*userLeafNode); ok {
			// reached to a leaf node
			break
		}
		direction := getNthBit(lookupIndex, position)
		if direction {
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		position++
	}

	if _, ok := nodePointer.(*userLeafNode); ok && nodePointer != nil {
		if nodePointer.(*userLeafNode).key == key {
			return nodePointer.(*userLeafNode)
		}
	}
	return nil
}

func (m *MerkleTree) Set(ops Operation) error {
	index := m.computePrivateIndex(ops.Key)
	toAdd := userLeafNode{
		key:   ops.Key,
		value: ops.Value,
		index: index,
	}

	return m.insertNode(index, &toAdd)
}

// Private Index calculation function
// would be replaced with Ismail's VRF implementation
func (m *MerkleTree) computePrivateIndex(key string) []byte {
	stringBytes := append([]byte(nil), key...)
	return m.digest(stringBytes)
}

func (m *MerkleTree) insertNode(key []byte, node *userLeafNode) error {
	position := 0
	var nodePointer interface{}
	nodePointer = m.root

insertLoop:
	for {
		node.level++
		switch nodePointer.(type) {
		case *userLeafNode:
			// reached a "bottom" of the tree.
			// add a new interior node and push the previous leaf down
			// then continue insertion
			currentNodeUL := nodePointer.(*userLeafNode)
			if currentNodeUL.parent == nil {
				return ErrInvalidTree
			}
			newInteriorNode := interiorNode{
				parent: currentNodeUL.parent,
				level:  currentNodeUL.level,
			}

			if currentNodeUL.key == node.key {
				// replace the value
				currentNodeUL.value = node.value
				return nil
			}

			currentNodeKey := m.computePrivateIndex(currentNodeUL.key)

			currentNodeUL.index = currentNodeKey

			direction := getNthBit(currentNodeKey, position)
			if direction {
				newInteriorNode.rightChild = currentNodeUL
			} else {
				newInteriorNode.leftChild = currentNodeUL
			}
			currentNodeUL.level++
			currentNodeUL.parent = &newInteriorNode
			if newInteriorNode.parent.leftChild == nodePointer {
				newInteriorNode.parent.leftChild = &newInteriorNode
			} else {
				newInteriorNode.parent.rightChild = &newInteriorNode
			}
			nodePointer = &newInteriorNode
			node.level--
		case *interiorNode:
			currentNodeI := nodePointer.(*interiorNode)
			direction := getNthBit(key, position)

			if direction { // go right
				currentNodeI.rightHash = nil
				if currentNodeI.rightChild == nil {
					currentNodeI.rightChild = node
					node.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.leftHash = nil
				if currentNodeI.leftChild == nil {
					currentNodeI.leftChild = node
					node.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.leftChild
				}
			}
			position++
		default:
			return ErrInvalidTree
		}
	}
	return nil
}

func (m *MerkleTree) RecomputeHash() {
	m.computeHash([]bool{})
}

func (m *MerkleTree) computeHash(prefixBits []bool) {
	if m.root.leftHash == nil {
		m.root.leftHash = m.hashNode(
			append(prefixBits, false), m.root.leftChild)
	}
	if m.root.rightHash == nil {
		m.root.rightHash = m.hashNode(
			append(prefixBits, true), m.root.rightChild)
	}
}

func (m *MerkleTree) hashNode(prefixBits []bool, node interface{}) []byte {
	if node == nil {
		// empty node
		return hashEmptyNode(m, prefixBits)
	}

	switch node.(type) {
	case *interiorNode:
		currentNodeI := node.(*interiorNode)
		if currentNodeI.leftHash == nil {
			currentNodeI.leftHash = m.hashNode(
				append(prefixBits, false), currentNodeI.leftChild)
		}
		if currentNodeI.rightHash == nil {
			currentNodeI.rightHash = m.hashNode(
				append(prefixBits, true), currentNodeI.rightChild)
		}
		return hashInteriorNode(m, currentNodeI)
	case *userLeafNode:
		return hashLeafNode(m, node.(*userLeafNode))
	}
	return nil
}

func (m *MerkleTree) digest(input []byte) []byte {
	h := m.hash.Hash
	defer h.Reset()
	h.Write(input)
	return h.Sum(nil)
}

// Node manipulation functions

func hashInteriorNode(m *MerkleTree, node *interiorNode) []byte {
	var input []byte
	input = append(input, node.leftHash...)
	input = append(input, node.rightHash...)
	return m.digest(input)
}

func hashLeafNode(m *MerkleTree, node *userLeafNode) []byte {
	commit := append([]byte{}, m.salt...)
	commit = append(commit, node.key...)
	commit = append(commit, node.value...)
	commit = m.digest(commit)

	input := []byte{LeafIdentifier}                  // K_leaf
	input = append(input, m.treeNonce...)            // K_n
	input = append(input, node.index...)             // i
	input = append(input, intToBytes(node.level)...) // l
	input = append(input, commit...)                 // commit(key|| value)

	return m.digest(input)
}

func hashEmptyNode(m *MerkleTree, prefixBits []bool) []byte {
	input := []byte{EmptyBranchIdentifier}                // K_empty
	input = append(input, m.treeNonce...)                 // K_n
	input = append(input, toBytes(prefixBits)...)         // i
	input = append(input, intToBytes(len(prefixBits))...) // l

	return m.digest(input)
}

var _ MerkleNode = (*userLeafNode)(nil)

func (node *userLeafNode) Value() []byte {
	return node.value
}
