package merkletree

type AuthenticationPath struct {
	treeNonce    []byte
	prunedHashes [][]byte
	index        []byte
	lookupIndex  []byte
	level        int
	leaf         ProofNode
}

func (ap *AuthenticationPath) TreeNonce() []byte {
	return ap.treeNonce
}

func (ap *AuthenticationPath) PrunedTree() [][]byte {
	return ap.prunedHashes
}

func (ap *AuthenticationPath) Index() []byte {
	return ap.index
}

func (ap *AuthenticationPath) LookUpIndex() []byte {
	return ap.lookupIndex
}

func (ap *AuthenticationPath) Level() int {
	return ap.level
}

func (ap *AuthenticationPath) Leaf() ProofNode {
	return ap.leaf
}
