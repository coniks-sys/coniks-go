package protocol

import (
	"bytes"
)

type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

func (tb *TemporaryBinding) Serialize(strSig []byte) []byte {
	var tbBytes []byte
	tbBytes = append(tbBytes, strSig...)
	tbBytes = append(tbBytes, tb.Index...)
	tbBytes = append(tbBytes, tb.Value...)
	return tbBytes
}

// Verify validates the received tb by comparing
// index, value against the Index and Value
// of tb. value could be nil if we have no information about
// the existed binding (TOFU).
func (tb *TemporaryBinding) Verify(index, value []byte) bool {
	return bytes.Equal(tb.Index, index) &&
		(value != nil && bytes.Equal(tb.Value, value))
}
