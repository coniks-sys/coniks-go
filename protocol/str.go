package protocol

import (
	"encoding/json"

	"github.com/coniks-sys/coniks-go/merkletree"
)

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

// VerifyHashChain wraps merkletree.SignedTreeRoot.VerifyHashChain
func (str *DirSTR) VerifyHashChain(savedSTR *DirSTR) bool {
	return str.SignedTreeRoot.VerifyHashChain(savedSTR.SignedTreeRoot)
}

// UnmarshalJSON fills in the unexported Ad interface from the underlying
// merkletree.SignedTreeRoot.  This is necessary since, for now, Serialize
// and VerifyHashChain dispatch to methods which dereference it.
func (str *DirSTR) UnmarshalJSON(m []byte) error {
	// Use an alias to avoid an infinite loop
	type DirSTR2 DirSTR
	str2 := &DirSTR2{}
	if err := json.Unmarshal(m, str2); err != nil {
		return err
	}
	str2.Ad = str2.Policies
	*str = DirSTR(*str2)
	return nil
}
