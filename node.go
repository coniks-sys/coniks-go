package merkletree

type interiorNode struct {
	parent     *interiorNode
	leftChild  MerkleNode
	rightChild MerkleNode
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

type emptyNode struct {
	interiorNode
}

type MerkleNode interface {
	Value() []byte
	isEmpty() bool
}

type LookUpProofNode interface {
	GetHash() []byte
}

var _ MerkleNode = (*userLeafNode)(nil)
var _ MerkleNode = (*interiorNode)(nil)
var _ MerkleNode = (*emptyNode)(nil)

func (node *userLeafNode) Value() []byte {
	return node.value
}

func (node *userLeafNode) isEmpty() bool {
	return false
}

func (node *interiorNode) Value() []byte {
	return nil
}

func (node *interiorNode) isEmpty() bool {
	return false
}

func (node *emptyNode) Value() []byte {
	return nil
}

func (node *emptyNode) isEmpty() bool {
	return true
}

var _ LookUpProofNode = (*userLeafNode)(nil)
var _ LookUpProofNode = (*interiorNode)(nil)
var _ LookUpProofNode = (*emptyNode)(nil)

func (node *userLeafNode) GetHash() []byte {
	if node.parent.leftChild == node {
		return node.parent.leftHash
	}
	return node.parent.rightHash
}

func (node *interiorNode) GetHash() []byte {
	if node.parent.leftChild == node {
		return node.parent.leftHash
	}
	return node.parent.rightHash
}

func (node *emptyNode) GetHash() []byte {
	if node.parent.leftChild == node {
		return node.parent.leftHash
	}
	return node.parent.rightHash
}

func (node *interiorNode) serialize() []byte {
	input := make([]byte, 0, len(node.leftHash)+len(node.rightHash))
	input = append(input, node.leftHash...)
	input = append(input, node.rightHash...)
	return input
}

func (node *interiorNode) hash(m *MerkleTree) []byte {
	return Digest(node.serialize())
}

func (node *userLeafNode) hash(m *MerkleTree) []byte {
	return Digest(
		[]byte{LeafIdentifier},         // K_leaf
		[]byte(m.treeNonce),            // K_n
		[]byte(node.index),             // i
		[]byte(IntToBytes(node.level)), // l
		[]byte(node.commitment),        // commit(key|| value)
	)
}

func (node *emptyNode) hash(m *MerkleTree, prefixBits []bool) []byte {
	return Digest(
		[]byte{EmptyBranchIdentifier},       // K_empty
		[]byte(m.treeNonce),                 // K_n
		[]byte(ToBytes(prefixBits)),         // i
		[]byte(IntToBytes(len(prefixBits))), // l
	)
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
		case *emptyNode:
			newNode.leftChild = node.leftChild.(*emptyNode).clone(newNode)
		}
	}

	if node.rightChild != nil {
		switch node.rightChild.(type) {
		case *interiorNode:
			newNode.rightChild = node.rightChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.rightChild = node.rightChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.rightChild = node.rightChild.(*emptyNode).clone(newNode)
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

func (node *emptyNode) clone(parent *interiorNode) *emptyNode {
	newNode := &emptyNode{
		interiorNode: interiorNode{
			parent: parent,
			level:  node.level,
		},
	}

	return newNode
}
