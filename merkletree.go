package merkletree

import "errors"

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
	privKey   []byte
	pubKey    []byte
	root      *interiorNode
}

func InitMerkleTree(treeNonce, salt, pubKey, privKey []byte) *MerkleTree {
	leftBranch := &emptyNode{
		interiorNode: interiorNode{
			level: 1,
		},
	}

	rightBranch := &emptyNode{
		interiorNode: interiorNode{
			level: 1,
		},
	}
	root := &interiorNode{
		parent:     nil,
		leftChild:  leftBranch,
		rightChild: rightBranch,
		leftHash:   nil,
		rightHash:  nil,
		level:      0,
	}
	leftBranch.parent = root
	rightBranch.parent = root

	m := &MerkleTree{
		treeNonce: treeNonce,
		salt:      salt,
		root:      root,
		privKey:   privKey,
		pubKey:    pubKey,
	}
	return m
}

func LookUp(key string) (MerkleNode, []LookUpProofNode, error) {
	str := getCurrentSTR()
	return lookUp(key, str)
}

func LookUpInEpoch(key string, ep int64) (MerkleNode, []LookUpProofNode, error) {
	str := GetSTR(ep)
	return lookUp(key, str)
}

func lookUp(key string, str *SignedTreeRoot) (MerkleNode, []LookUpProofNode, error) {
	lookupIndex := computePrivateIndex(key)
	position := 0
	var nodePointer interface{}
	nodePointer = str.treeRoot
	var proof []LookUpProofNode

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
		direction := getNthBit(lookupIndex, position)
		if direction {
			nodePointer = nodePointer.(*interiorNode).rightChild
		} else {
			nodePointer = nodePointer.(*interiorNode).leftChild
		}
		position++
	}

	if nodePointer == nil {
		return nil, nil, ErrInvalidTree
	}
	switch nodePointer.(type) {
	case *userLeafNode:
		proof = append(proof, nodePointer.(*userLeafNode))
		if nodePointer.(*userLeafNode).key == key {
			return nodePointer.(*userLeafNode), proof, nil
		}
		// reached a different leaf with a matching prefix
		// return nil and a auth path including the leaf node
		return nil, proof, nil
	case *emptyNode:
		proof = append(proof, nodePointer.(*emptyNode))
		return nil, proof, nil
	}
	return nil, nil, ErrInvalidTree
}

func (m *MerkleTree) Set(key string, value []byte) error {
	index := computePrivateIndex(key)
	toAdd := userLeafNode{
		key:        key,
		value:      value,
		index:      index,
		commitment: commitment(m.salt, key, value),
	}

	return m.insertNode(index, &toAdd)
}

// Private Index calculation function
// would be replaced with Ismail's VRF implementation
func computePrivateIndex(key string) []byte {
	return Digest([]byte(key))
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

			leftBranch := &emptyNode{
				interiorNode: interiorNode{
					level: currentNodeUL.level + 1,
				},
			}
			rightBranch := &emptyNode{
				interiorNode: interiorNode{
					level: currentNodeUL.level + 1,
				},
			}
			newInteriorNode := interiorNode{
				parent:     currentNodeUL.parent,
				level:      currentNodeUL.level,
				leftChild:  leftBranch,
				rightChild: rightBranch,
			}
			leftBranch.parent = &newInteriorNode
			rightBranch.parent = &newInteriorNode

			if currentNodeUL.key == node.key {
				// replace the value
				currentNodeUL.value = node.value
				return nil
			}

			currentNodeKey := computePrivateIndex(currentNodeUL.key)

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
				if currentNodeI.rightChild.isEmpty() {
					currentNodeI.rightChild = node
					node.parent = currentNodeI
					break insertLoop
				} else {
					nodePointer = currentNodeI.rightChild
				}
			} else { // go left
				currentNodeI.leftHash = nil
				if currentNodeI.leftChild.isEmpty() {
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
	var prefixBits []bool
	if m.root.leftHash == nil {
		m.root.leftHash = m.hashNode(
			append(prefixBits, false), m.root.leftChild)
	}
	if m.root.rightHash == nil {
		m.root.rightHash = m.hashNode(
			append(prefixBits, true), m.root.rightChild)
	}
}

func (m *MerkleTree) hashNode(prefixBits []bool, node MerkleNode) []byte {
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
		return currentNodeI.hash(m)
	case *userLeafNode:
		return node.(*userLeafNode).hash(m)
	case *emptyNode:
		return node.(*emptyNode).hash(m, prefixBits)
	}
	return nil
}

func (m *MerkleTree) Clone() *MerkleTree {
	return &MerkleTree{
		treeNonce: m.treeNonce,
		salt:      m.salt,
		root:      m.root.clone(nil),
		privKey:   m.privKey,
		pubKey:    m.pubKey,
	}
}
