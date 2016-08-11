package merkletree

import (
	"bytes"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	ErrorInvalidTree = errors.New("[merkletree] invalid tree")
)

const (
	EmptyBranchIdentifier = 'E'
	LeafIdentifier        = 'L'
)

type MerkleTree struct {
	nonce []byte
	root  *interiorNode
	hash  []byte
}

func NewMerkleTree() (*MerkleTree, error) {
	root := NewInteriorNode(nil, 0, []bool{})
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

func (m *MerkleTree) Get(lookupIndex []byte) *AuthenticationPath {
	lookupIndexBits := util.ToBits(lookupIndex)
	depth := 0
	var nodePointer MerkleNode
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
		panic(ErrorInvalidTree)
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		pNode := nodePointer.(*userLeafNode).Clone(nil).(*userLeafNode)
		authPath.Leaf = pNode
		if bytes.Equal(nodePointer.(*userLeafNode).index, lookupIndex) {
			return authPath
		}
		// reached a different leaf with a matching prefix
		// return a auth path including the leaf node without salt & value
		pNode.value = nil
		pNode.salt = nil
		return authPath
	case *emptyNode:
		authPath.Leaf = nodePointer.(*emptyNode).Clone(nil).(*emptyNode)
		return authPath
	}
	panic(ErrorInvalidTree)
}

func (m *MerkleTree) Set(index []byte, key string, value []byte) error {
	// generate random per user salt
	salt, err := crypto.MakeRand()
	if err != nil {
		return err
	}

	toAdd := userLeafNode{
		key:        key,
		value:      append([]byte{}, value...), // make a copy of value
		index:      index,
		salt:       salt,
		commitment: crypto.Digest(salt, []byte(key), value),
	}

	m.insertNode(index, &toAdd)
	return nil
}

func (m *MerkleTree) insertNode(index []byte, toAdd *userLeafNode) {
	indexBits := util.ToBits(index)
	var depth uint32 // = 0
	var nodePointer MerkleNode
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
				panic(ErrorInvalidTree)
			}

			if bytes.Equal(currentNodeUL.index, toAdd.index) {
				// replace the value
				toAdd.parent = currentNodeUL.parent
				toAdd.level = currentNodeUL.level
				*currentNodeUL = *toAdd
				return
			}

			newInteriorNode := NewInteriorNode(currentNodeUL.parent, depth, indexBits[:depth])

			direction := util.GetNthBit(currentNodeUL.index, depth)
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
			panic(ErrorInvalidTree)
		}
	}
}

// visits all leaf-nodes and calls callBack on each of them
// doesn't modify the underlying tree m
func (m *MerkleTree) visitLeafNodes(callBack func(*userLeafNode)) {
	visitULNsInternal(m.root, callBack)
}

func visitULNsInternal(nodePtr MerkleNode, callBack func(*userLeafNode)) {
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
		panic(ErrorInvalidTree)
	}
}

func (m *MerkleTree) recomputeHash() {
	m.hash = m.root.Hash(m)
}

func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		nonce: m.nonce,
		root:  m.root.Clone(nil).(*interiorNode),
		hash:  append([]byte{}, m.hash...),
	}
}
