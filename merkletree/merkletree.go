package merkletree

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

var (
	ErrorInvalidTree  = errors.New("[merkletree] Invalid tree")
	ErrorBadTreeNonce = errors.New("[merkletree] Bad tree nonce")
)

const (
	EmptyBranchIdentifier  = 'E'
	LeafIdentifier         = 'L'
	InteriorNodeIdentifier = 'I'
	NodeKeyIdentifier      = 'N'
	STRIdentifier          = 'S'
	EpochIdentifier        = "EI"
	TreeNonceIdentifier    = "TN"
)

type MerkleTree struct {
	nonce []byte
	root  *interiorNode
	hash  []byte
}

func NewMerkleTree() (*MerkleTree, error) {
	root := NewInteriorNode(nil, 0, []bool{})
	nonce := make([]byte, crypto.HashSizeByte)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	m := &MerkleTree{
		nonce: nonce,
		root:  root,
	}
	return m, nil
}

func (m *MerkleTree) Get(key string) *AuthenticationPath {
	lookupIndex := computePrivateIndex(key)
	lookupIndexBits := util.ToBits(lookupIndex)
	depth := 0
	var nodePointer interface{}
	nodePointer = m.root

	authPath := &AuthenticationPath{
		treeNonce:   m.nonce,
		lookupIndex: lookupIndex,
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
		if direction {
			authPath.prunedHashes = append(authPath.prunedHashes,
				nodePointer.(*interiorNode).leftHash)
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			authPath.prunedHashes = append(authPath.prunedHashes,
				nodePointer.(*interiorNode).rightHash)
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		depth++
	}

	if nodePointer == nil {
		panic(ErrorInvalidTree)
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		pNode := nodePointer.(*userLeafNode).Clone(nil).(*userLeafNode)
		authPath.leaf = pNode
		if bytes.Equal(nodePointer.(*userLeafNode).index, lookupIndex) {
			return authPath
		}
		// reached a different leaf with a matching prefix
		// return a auth path including the leaf node
		pNode.value = nil
		return authPath
	case *emptyNode:
		authPath.leaf = nodePointer.(*emptyNode).Clone(nil).(*emptyNode)
		return authPath
	}
	panic(ErrorInvalidTree)
}

func (m *MerkleTree) Set(key string, value []byte) error {
	index := computePrivateIndex(key)

	// generate random per user salt
	salt := make([]byte, crypto.HashSizeByte)
	if _, err := rand.Read(salt); err != nil {
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

// Private Index calculation function
// would be replaced with Ismail's VRF implementation
func computePrivateIndex(key string) []byte {
	return crypto.Digest([]byte(key))
}

func (m *MerkleTree) insertNode(index []byte, toAdd *userLeafNode) {
	indexBits := util.ToBits(index)
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

func (m *MerkleTree) recomputeHash() {
	m.hash = m.root.Hash(m)
}

func (m *MerkleTree) GetHash() []byte {
	return m.hash
}

func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		nonce: m.nonce,
		root:  m.root.Clone(nil).(*interiorNode),
	}
}
