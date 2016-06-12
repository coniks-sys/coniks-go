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
}

type MerkleNode interface {
	Value() []byte
	IsEmpty() bool
}

var _ MerkleNode = (*userLeafNode)(nil)
var _ MerkleNode = (*interiorNode)(nil)
var _ MerkleNode = (*emptyNode)(nil)

func (node *userLeafNode) Value() []byte {
	return node.value
}

func (node *userLeafNode) IsEmpty() bool {
	return false
}

func (node *interiorNode) Value() []byte {
	return nil
}

func (node *interiorNode) IsEmpty() bool {
	return false
}

func (node *emptyNode) Value() []byte {
	return nil
}

func (node *emptyNode) IsEmpty() bool {
	return true
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
		[]byte(intToBytes(node.level)), // l
		[]byte(node.commitment),        // commit(key|| value)
	)
}

func (node *emptyNode) hash(m *MerkleTree, prefixBits []bool) []byte {
	return Digest(
		[]byte{EmptyBranchIdentifier},       // K_empty
		[]byte(m.treeNonce),                 // K_n
		[]byte(toBytes(prefixBits)),         // i
		[]byte(intToBytes(len(prefixBits))), // l
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
			newNode.leftChild = new(emptyNode)
		}
	}

	if node.rightChild != nil {
		switch node.rightChild.(type) {
		case *interiorNode:
			newNode.rightChild = node.rightChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.rightChild = node.rightChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.rightChild = new(emptyNode)
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
