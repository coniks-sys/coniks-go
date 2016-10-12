package merkletree

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type TemporaryBinding struct {
	// IssuedEpoch would not be included in the serialization.
	// To verify the validation of IssuedEpoch, we can compare it
	// against the epoch of STR included in the serialization.
	IssuedEpoch uint64
	Index       []byte
	Value       []byte
	Signature   []byte
}

func NewTB(key sign.PrivateKey, ep uint64, strSig, index, value []byte) *TemporaryBinding {
	tb := &TemporaryBinding{
		IssuedEpoch: ep,
		Index:       index,
		Value:       value,
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

func (tb *TemporaryBinding) Verify(ap *AuthenticationPath) bool {
	// compare TB's index with authentication path's index (after Update)
	if !bytes.Equal(ap.LookupIndex, tb.Index) ||
		!bytes.Equal(ap.Leaf.Value, tb.Value) {
		return false
	}
	return true
}
