package merkletree

type node struct {
	parent MerkleNode
	level  int
}

type interiorNode struct {
	node
	leftChild  MerkleNode
	rightChild MerkleNode
}

type userLeafNode struct {
	node
	key        string
	value      []byte
	salt       []byte
	index      []byte
	commitment []byte
}

type emptyNode struct {
	node
}

func NewInteriorNode(parent MerkleNode, level int) *interiorNode {
	leftBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
	}

	rightBranch := &emptyNode{
		node: node{
			level: level + 1,
		},
	}
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  level,
		},
		leftChild:  leftBranch,
		rightChild: rightBranch,
	}
	leftBranch.parent = newNode
	rightBranch.parent = newNode

	return newNode
}

type MerkleNode interface {
	Value() []byte
	isEmpty() bool
}

type ProofNode interface {
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

var _ ProofNode = (*node)(nil)

func (n *interiorNode) clone(parent *interiorNode) *interiorNode {
	newNode := &interiorNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
	}

	if n.leftChild != nil {
		switch n.leftChild.(type) {
		case *interiorNode:
			newNode.leftChild = n.leftChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.leftChild = n.leftChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.leftChild = n.leftChild.(*emptyNode).clone(newNode)
		}
	}

	if n.rightChild != nil {
		switch n.rightChild.(type) {
		case *interiorNode:
			newNode.rightChild = n.rightChild.(*interiorNode).clone(newNode)
		case *userLeafNode:
			newNode.rightChild = n.rightChild.(*userLeafNode).clone(newNode)
		case *emptyNode:
			newNode.rightChild = n.rightChild.(*emptyNode).clone(newNode)
		}
	}

	return newNode
}

func (n *userLeafNode) clone(parent *interiorNode) *userLeafNode {
	return &userLeafNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
		key:        n.key,
		value:      n.value,
		salt:       n.salt,
		index:      append([]byte{}, n.index...), // make a copy of index
		commitment: n.commitment,
	}
}

func (n *emptyNode) clone(parent *interiorNode) *emptyNode {
	return &emptyNode{
		node: node{
			parent: parent,
			level:  n.level,
		},
	}
}
