package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

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

// VerifyHashChain computes the hash of savedSTR's signature,
// and compares it to the hash of previous STR included
// in the issued STR. The hash chain is valid if
// these two hash values are equal and consecutive.
func (str *DirSTR) VerifyHashChain(savedSTR *DirSTR) bool {
	hash := crypto.Digest(savedSTR.Signature)
	return str.PreviousEpoch == savedSTR.Epoch &&
		str.Epoch == savedSTR.Epoch+1 &&
		bytes.Equal(hash, str.PreviousSTRHash)
}
