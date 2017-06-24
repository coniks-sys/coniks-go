package merkletree

import (
	"bytes"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/hashers"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	// ErrInvalidTree indicates a panic due to
	// a malformed operation on the tree.
	ErrInvalidTree = errors.New("[merkletree] Invalid tree")
)

// MerkleTree represents the Merkle prefix tree data structure,
// which includes the root node, its hash, and a random tree-specific
// nonce.
type MerkleTree struct {
	nonce []byte
	root  *interiorNode
	hash  []byte
}

// NewMerkleTree returns an empty Merkle prefix tree
// with a secure random nonce. The tree root is an interior node
// and its children are two empty leaf nodes.
func NewMerkleTree() (*MerkleTree, error) {
	root := newInteriorNode(nil, 0, []bool{})
	nonce, err := crypto.MakeRand()
	if err != nil {
		return nil, err
	}
	m := &MerkleTree{
		nonce: nonce,
		root:  root,
	}
	return m, nil
}

// Get returns an AuthenticationPath used as a proof
// of inclusion/absence for the requested lookupIndex.
func (m *MerkleTree) Get(lookupIndex []byte) *AuthenticationPath {
	lookupIndexBits := utils.ToBits(lookupIndex)
	depth := 0
	var nodePointer merkleNode
	nodePointer = m.root

	authPath := &AuthenticationPath{
		TreeNonce:   m.nonce,
		LookupIndex: lookupIndex,
	}

	for {
		if _, ok := nodePointer.(*userLeafNode); ok {
			// reached to a leaf node
			break
		}
		if _, ok := nodePointer.(*emptyNode); ok {
			// reached to an empty branch
			break
		}
		direction := lookupIndexBits[depth]
		var hashArr hashers.Hash
		if direction {
			copy(hashArr[:], nodePointer.(*interiorNode).leftHash)
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			copy(hashArr[:], nodePointer.(*interiorNode).rightHash)
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		authPath.PrunedTree = append(authPath.PrunedTree, hashArr)
		depth++
	}

	if nodePointer == nil {
		panic(ErrInvalidTree)
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		pNode := nodePointer.(*userLeafNode)
		authPath.Leaf = &ProofNode{
			Level:   pNode.level,
			Index:   pNode.index,
			Value:   pNode.value,
			IsEmpty: false,
			Commitment: &crypto.Commit{
				Salt:  pNode.commitment.Salt,
				Value: pNode.commitment.Value,
			},
		}
		if bytes.Equal(nodePointer.(*userLeafNode).index, lookupIndex) {
			return authPath
		}
		// reached a different leaf with a matching prefix
		// return a auth path including the leaf node without salt & value
		authPath.Leaf.Value = nil
		authPath.Leaf.Commitment.Salt = nil
		return authPath
	case *emptyNode:
		pNode := nodePointer.(*emptyNode)
		authPath.Leaf = &ProofNode{
			Level:      pNode.level,
			Index:      pNode.index,
			Value:      nil,
			IsEmpty:    true,
			Commitment: nil,
		}
		return authPath
	}
	panic(ErrInvalidTree)
}

// Set inserts or updates the value of the given index
// calculated from the key to the tree. It will generate a new commitment
// for the leaf node. In the case of an update, the leaf node's value and
// commitment are replaced with the new value and newly generated
// commitment.
func (m *MerkleTree) Set(index []byte, key string, value []byte) error {
	commitment, err := crypto.NewCommit([]byte(key), value)
	if err != nil {
		return err
	}
	toAdd := userLeafNode{
		key:        key,
		value:      append([]byte{}, value...), // make a copy of value
		index:      index,
		commitment: commitment,
	}
	m.insertNode(index, &toAdd)
	return nil
}

func (m *MerkleTree) insertNode(index []byte, toAdd *userLeafNode) {
	indexBits := utils.ToBits(index)
	var depth uint32 // = 0
	var nodePointer merkleNode
	nodePointer = m.root

insertLoop:
	for {
		switch nodePointer.(type) {
		case *userLeafNode:
			// reached a "bottom" of the tree.
			// add a new interior node and push the previous leaf down
			// then continue insertion
			currentNodeUL := nodePointer.(*userLeafNode)
			if currentNodeUL.parent == nil {
				panic(ErrInvalidTree)
			}

			if bytes.Equal(currentNodeUL.index, toAdd.index) {
				// replace the value
				toAdd.parent = currentNodeUL.parent
				toAdd.level = currentNodeUL.level
				*currentNodeUL = *toAdd
				return
			}

			newInteriorNode := newInteriorNode(currentNodeUL.parent, depth, indexBits[:depth])

			direction := utils.GetNthBit(currentNodeUL.index, depth)
			if direction {
				newInteriorNode.rightChild = currentNodeUL
			} else {
				newInteriorNode.leftChild = currentNodeUL
			}
			currentNodeUL.level = depth + 1
			currentNodeUL.parent = newInteriorNode
			if newInteriorNode.parent.(*interiorNode).leftChild == nodePointer {
				newInteriorNode.parent.(*interiorNode).leftChild = newInteriorNode
			} else {
				newInteriorNode.parent.(*interiorNode).rightChild = newInteriorNode
			}
			nodePointer = newInteriorNode
		case *interiorNode:
			currentNodeI := nodePointer.(*interiorNode)
			direction := indexBits[depth]
			if direction { // go right
				currentNodeI.rightHash = nil
				if currentNodeI.rightChild.isEmpty() {
					currentNodeI.rightChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.leftHash = nil
				if currentNodeI.leftChild.isEmpty() {
					currentNodeI.leftChild = toAdd
					toAdd.level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.leftChild
				}
			}
			depth += 1
		default:
			panic(ErrInvalidTree)
		}
	}
}

// visits all leaf-nodes and calls callBack on each of them
// doesn't modify the underlying tree m
func (m *MerkleTree) visitLeafNodes(callBack func(*userLeafNode)) {
	visitULNsInternal(m.root, callBack)
}

func visitULNsInternal(nodePtr merkleNode, callBack func(*userLeafNode)) {
	switch nodePtr.(type) {
	case *userLeafNode:
		callBack(nodePtr.(*userLeafNode))
	case *interiorNode:
		if leftChild := nodePtr.(*interiorNode).leftChild; leftChild != nil {
			visitULNsInternal(leftChild, callBack)
		}
		if rightChild := nodePtr.(*interiorNode).rightChild; rightChild != nil {
			visitULNsInternal(rightChild, callBack)
		}
	case *emptyNode:
		// do nothing
	default:
		panic(ErrInvalidTree)
	}
}

func (m *MerkleTree) recomputeHash() {
	m.hash = m.root.hash(m)
}

// Clone returns a copy of the tree m.
// Any later change to the original tree m does not affect the cloned tree,
// and vice versa.
func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		nonce: m.nonce,
		root:  m.root.clone(nil).(*interiorNode),
		hash:  append([]byte{}, m.hash...),
	}
}
