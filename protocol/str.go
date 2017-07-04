package protocol

import "github.com/coniks-sys/coniks-go/merkletree"

// DirSTR disambiguates merkletree.SignedTreeRoot's AssocData interface,
// for the purpose of exporting and unmarshalling.
type DirSTR struct {
	*merkletree.SignedTreeRoot
	Policies *Policies
}

// NewDirSTR constructs a new DirSTR from a merkletree.SignedTreeRoot
func NewDirSTR(str *merkletree.SignedTreeRoot) *DirSTR {
	return &DirSTR{
		str,
		str.Ad.(*Policies),
	}
}

// Serialize overrides merkletree.SignedTreeRoot.Serialize
func (str *DirSTR) Serialize() []byte {
	return append(str.SerializeInternal(), str.Policies.Serialize()...)
}

// VerifyHashChain wraps merkletree.SignedTreeRoot.VerifyHashChain
func (str *DirSTR) VerifyHashChain(savedSTR *DirSTR) bool {
	return str.SignedTreeRoot.VerifyHashChain(savedSTR.SignedTreeRoot)
}
