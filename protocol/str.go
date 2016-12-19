package protocol

import "github.com/coniks-sys/coniks-go/merkletree"

type DirSTR struct {
	merkletree.SignedTreeRoot
	Policies *Policies
}

func NewDirSTR(str *merkletree.SignedTreeRoot) *DirSTR {
	return &DirSTR{
		*str,
		str.Ad.(*Policies),
	}
}

func (str *DirSTR) VerifyHashChain(savedSTR *DirSTR) bool {
	return str.SignedTreeRoot.VerifyHashChain(&savedSTR.SignedTreeRoot)
}
