// Defines a temporary binding

package protocol

import (
	"bytes"
)

// A TemporaryBinding consists of the private
// Index for a username, the Value (i.e. public key etc.)
// mapped to this index in a key directory, and a digital
// Signature.
//
// A TB serves as a proof of registration and as a
// signed promise by a CONIKS server
// to include the corresponding name-to-key binding
// in the next directory snapshot. As such, TBs allow clients
// to begin using the contained name-to-key binding for
// encryption/signing without having to wait for the binding's inclusion
// in the next snapshot.
type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

// Serialize encodes the tb to a byte array with the following format:
// [strSig, tb.Index, tb.Value].
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
