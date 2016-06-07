package merkletree

import (
	"crypto"
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

type Scheme interface {
	Sign([]byte) []byte
	Verify(publicKey []byte, message, sig []byte) bool
}

type HashFunction struct {
	HashSizeByte int
	Hash         hash.Hash
	HashId       crypto.Hash
}

type MerkleTree struct {
	hash      HashFunction
	scheme    Scheme
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
	key        string
	value      []byte
	index      []byte
	commitment []byte
}

type MerkleNode interface {
	Value() []byte
}

func InitMerkleTree(treeNonce, salt []byte, hashFunc HashFunction, scheme Scheme) *MerkleTree {
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
		scheme:    scheme,
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

func (m *MerkleTree) Set(key string, value []byte) error {
	index := m.computePrivateIndex(key)
	toAdd := userLeafNode{
		key:        key,
		value:      value,
		index:      index,
		commitment: leafNodeCommitment(m, key, value),
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

var _ MerkleNode = (*userLeafNode)(nil)

func (node *userLeafNode) Value() []byte {
	return node.value
}

func (node *interiorNode) serialize() []byte {
	var input []byte
	input = append(input, node.leftHash...)
	input = append(input, node.rightHash...)
	return input
}

func leafNodeCommitment(m *MerkleTree, key string, value []byte) []byte {
	commit := append([]byte{}, m.salt...)
	commit = append(commit, key...)
	commit = append(commit, value...)
	return m.digest(commit)
}

func hashInteriorNode(m *MerkleTree, node *interiorNode) []byte {
	return m.digest(node.serialize())
}

func hashLeafNode(m *MerkleTree, node *userLeafNode) []byte {
	input := []byte{LeafIdentifier}                  // K_leaf
	input = append(input, m.treeNonce...)            // K_n
	input = append(input, node.index...)             // i
	input = append(input, intToBytes(node.level)...) // l
	input = append(input, node.commitment...)        // commit(key|| value)
	return m.digest(input)
}

func hashEmptyNode(m *MerkleTree, prefixBits []bool) []byte {
	input := []byte{EmptyBranchIdentifier}                // K_empty
	input = append(input, m.treeNonce...)                 // K_n
	input = append(input, toBytes(prefixBits)...)         // i
	input = append(input, intToBytes(len(prefixBits))...) // l
	return m.digest(input)
}

// tree clone methods

func (m *MerkleTree) clone() *MerkleTree {
	return &MerkleTree{
		treeNonce: m.treeNonce,
		salt:      m.salt,
		hash:      m.hash,
		scheme:    m.scheme,
		root:      m.root.clone(nil),
	}
}

func (node *interiorNode) clone(parent *interiorNode) *interiorNode {
	newNode := &interiorNode{
		parent:    parent,
		level:     node.level,
		leftHash:  node.leftHash,
		rightHash: node.rightHash,
	}

	if node.leftChild != nil {
		switch node.leftChild.(type) {
		case *interiorNode:
			newNode.leftChild = node.leftChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.leftChild = node.leftChild.(*userLeafNode).clone(newNode)
		}
	}

	if node.rightChild != nil {
		switch node.rightChild.(type) {
		case *interiorNode:
			newNode.rightChild = node.rightChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.rightChild = node.rightChild.(*userLeafNode).clone(newNode)
		}
	}

	return newNode
}

func (node *userLeafNode) clone(parent *interiorNode) *userLeafNode {
	newNode := &userLeafNode{
		key:        node.key,
		value:      node.value,
		index:      append([]byte{}, node.index...), // make a copy of index
		commitment: node.commitment,
	}
	newNode.parent = parent
	newNode.level = node.level

	return newNode
}
