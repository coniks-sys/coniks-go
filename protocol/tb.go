// Defines a temporary binding

package protocol

// A TemporaryBinding consists of the private
// Index for a username, the Value (i.e. public key etc.)
// mapped to this index in a key directory, and a digital
// Signature of these fields.
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

// Serialize serializes the temporary binding into
// a specified format.
func (tb *TemporaryBinding) Serialize(strSig []byte) []byte {
	var tbBytes []byte
	tbBytes = append(tbBytes, strSig...)
	tbBytes = append(tbBytes, tb.Index...)
	tbBytes = append(tbBytes, tb.Value...)
	return tbBytes
}
