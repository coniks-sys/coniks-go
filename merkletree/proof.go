package merkletree

type AuthenticationPath struct {
	treeNonce    []byte
	prunedHashes [][]byte
	lookupIndex  []byte
	vrfProof     []byte
	leaf         ProofNode
}

func (ap *AuthenticationPath) TreeNonce() []byte {
	return ap.treeNonce
}

func (ap *AuthenticationPath) PrunedTree() [][]byte {
	return ap.prunedHashes
}

func (ap *AuthenticationPath) LookupIndex() []byte {
	return ap.lookupIndex
}

func (ap *AuthenticationPath) VrfProof() []byte {
	return ap.vrfProof
}

func (ap *AuthenticationPath) Leaf() ProofNode {
	return ap.leaf
}

type ProofNode interface {
	Level() int
	Index() []byte
	Value() []byte
	IsEmpty() bool
	Commitment() []byte
}

var _ ProofNode = (*userLeafNode)(nil)
var _ ProofNode = (*emptyNode)(nil)

func (n *emptyNode) Level() int {
	return n.level
}

func (n *emptyNode) Index() []byte {
	return n.index
}

func (n *emptyNode) Value() []byte {
	return nil
}

func (n *emptyNode) IsEmpty() bool {
	return true
}

func (n *emptyNode) Commitment() []byte {
	return nil
}

func (n *userLeafNode) Level() int {
	return n.level
}

func (n *userLeafNode) Index() []byte {
	return n.index
}

func (n *userLeafNode) Value() []byte {
	return n.value
}

func (n *userLeafNode) IsEmpty() bool {
	return false
}

func (n *userLeafNode) Commitment() []byte {
	return n.commitment
}
