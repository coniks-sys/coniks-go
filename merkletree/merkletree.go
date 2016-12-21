package merkletree

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	// ErrInvalidTree indicates a panic due to
	// a malformed operation on the tree.
	ErrInvalidTree = errors.New("[merkletree] Invalid tree")
)

const (
	// EmptyBranchIdentifier is the domain separation prefix for
	// empty node hashes.
	EmptyBranchIdentifier = 'E'

	// LeafIdentifier is the domain separation prefix for user
	// leaf node hashes.
	LeafIdentifier = 'L'
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
		var hashArr [crypto.HashSizeByte]byte
		if direction {
			copy(hashArr[:], nodePointer.(*interiorNode).LeftHash)
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			copy(hashArr[:], nodePointer.(*interiorNode).RightHash)
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
			Level:      pNode.Level,
			Index:      pNode.Index,
			Value:      pNode.Value,
			IsEmpty:    false,
			Commitment: &crypto.Commit{pNode.Commitment.Salt, pNode.Commitment.Value},
		}
		if bytes.Equal(nodePointer.(*userLeafNode).Index, lookupIndex) {
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
			Level:      pNode.Level,
			Index:      pNode.Index,
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
		Key:        key,
		Value:      append([]byte{}, value...), // make a copy of value
		Index:      index,
		Commitment: commitment,
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

			if bytes.Equal(currentNodeUL.Index, toAdd.Index) {
				// replace the value
				toAdd.parent = currentNodeUL.parent
				toAdd.Level = currentNodeUL.Level
				*currentNodeUL = *toAdd
				return
			}

			newInteriorNode := newInteriorNode(currentNodeUL.parent, depth, indexBits[:depth])

			direction := utils.GetNthBit(currentNodeUL.Index, depth)
			if direction {
				newInteriorNode.rightChild = currentNodeUL
			} else {
				newInteriorNode.leftChild = currentNodeUL
			}
			currentNodeUL.Level = depth + 1
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
				currentNodeI.RightHash = nil
				if currentNodeI.rightChild.isEmpty() {
					currentNodeI.rightChild = toAdd
					toAdd.Level = depth + 1
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.LeftHash = nil
				if currentNodeI.leftChild.isEmpty() {
					currentNodeI.leftChild = toAdd
					toAdd.Level = depth + 1
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

// encodeTree writes the tree's nonce into buff first,
// following by all the nodes data.
func encodeTree(buff io.Writer, m *MerkleTree) error {
	enc := gob.NewEncoder(buff)
	if err := enc.Encode(m.nonce); err != nil {
		return err
	}
	if err := encodeNode(enc, m.root); err != nil {
		return err
	}
	return nil
}

// decodeTree reconstructs the tree from the buffer
// that was written using encodeTree.
func decodeTree(buff io.Reader) (*MerkleTree, error) {
	m := new(MerkleTree)
	dec := gob.NewDecoder(buff)
	if err := dec.Decode(&m.nonce); err != nil {
		return nil, err
	}
	root, err := reconstructTree(dec, nil)
	if err != nil {
		return nil, err
	}
	m.root = root.(*interiorNode)
	m.hash = m.root.hash(m)
	return m, nil
}

func reconstructTree(dec *gob.Decoder, parent merkleNode) (merkleNode, error) {
	n, err := decodeNode(dec)
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
	n.(*interiorNode).leftChild, err = reconstructTree(dec, n)
	if err != nil {
		return nil, err
	}
	n.(*interiorNode).rightChild, err = reconstructTree(dec, n)
	if err != nil {
		return nil, err
	}
	return n, nil
}
