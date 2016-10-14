package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

func NewTB(key sign.PrivateKey, strSig, index, value []byte) *TemporaryBinding {
	tb := &TemporaryBinding{
		Index: index,
		Value: value,
	}
	tbPreSig := tb.Serialize(strSig)
	tb.Signature = key.Sign(tbPreSig)
	return tb
}

func (tb *TemporaryBinding) Serialize(strSig []byte) []byte {
	var tbBytes []byte
	tbBytes = append(tbBytes, strSig...)
	tbBytes = append(tbBytes, tb.Index...)
	tbBytes = append(tbBytes, tb.Value...)
	return tbBytes
}

// Verify verifies the issued temporary binding whether
// it was inserted as promised or not. This method should be
// called right after the directory has been updated, i.e., at the next epoch.
func (tb *TemporaryBinding) Verify(ap *AuthenticationPath) bool {
	// compare TB's index with authentication path's index (after Update)
	if !bytes.Equal(ap.LookupIndex, tb.Index) ||
		!bytes.Equal(ap.Leaf.Value, tb.Value) {
		return false
	}
	return true
}
