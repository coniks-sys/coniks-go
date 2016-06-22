package merkletree

import (
	"bytes"
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

var (
	ErrInvalidTree = errors.New("[merkletree] invalid tree")
)

const (
	EmptyBranchIdentifier = 'E'
	LeafIdentifier        = 'L'
)

type MerkleTree struct {
	treeNonce []byte
	salt      []byte
	policies  Policies
	root      *interiorNode
}

func InitMerkleTree(policies Policies, treeNonce, salt []byte) *MerkleTree {
	root := NewInteriorNode(nil, 0)

	m := &MerkleTree{
		treeNonce: treeNonce,
		salt:      salt,
		policies:  policies,
		root:      root,
	}
	return m
}

func (m *MerkleTree) Get(key string) (MerkleNode, []ProofNode) {
	lookupIndex := computePrivateIndex(key)
	depth := 0
	var nodePointer interface{}
	nodePointer = m.root
	var proof []ProofNode

	for {
		if _, ok := nodePointer.(*userLeafNode); ok {
			// reached to a leaf node
			break
		}
		if _, ok := nodePointer.(*emptyNode); ok {
			// reached to an empty branch
			break
		}
		proof = append(proof, nodePointer.(*interiorNode))
		direction := util.GetNthBit(lookupIndex, depth)
		if direction {
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		depth++
	}

	if nodePointer == nil {
		panic(ErrInvalidTree)
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		proof = append(proof, nodePointer.(*userLeafNode))
		if nodePointer.(*userLeafNode).key == key {
			return nodePointer.(*userLeafNode), proof
		}
		// reached a different leaf with a matching prefix
		// return nil and a auth path including the leaf node
		return nil, proof
	case *emptyNode:
		proof = append(proof, nodePointer.(*emptyNode))
		return nil, proof
	}
	panic(ErrInvalidTree)
}

func (m *MerkleTree) Set(key string, value []byte) {
	index := computePrivateIndex(key)
	toAdd := userLeafNode{
		key:        key,
		value:      value,
		index:      index,
		commitment: crypto.Digest(m.salt, []byte(key), value),
	}

	m.insertNode(index, &toAdd)
}

// Private Index calculation function
// would be replaced with Ismail's VRF implementation
func computePrivateIndex(key string) []byte {
	return crypto.Digest([]byte(key))
}

func (m *MerkleTree) insertNode(key []byte, toAdd *userLeafNode) {
	depth := 0
	var nodePointer interface{}
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
				currentNodeUL.value = toAdd.value
				currentNodeUL.commitment = toAdd.commitment
				return
			}

			newInteriorNode := NewInteriorNode(currentNodeUL.parent, depth)

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
			direction := util.GetNthBit(key, depth)

			if direction { // go right
				if currentNodeI.rightChild.isEmpty() {
					currentNodeI.rightChild = toAdd
					toAdd.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
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
	return
}

func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		treeNonce: m.treeNonce,
		salt:      m.salt,
		policies:  m.policies,
		root:      m.root.clone(nil),
	}
}
