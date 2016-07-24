package merkletree

import "github.com/coniks-sys/coniks-go/crypto"

type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

func NewTB(key crypto.SigningKey, index, indexProof, value, str []byte) *TemporaryBinding {
	tb := make([]byte, 0, len(str)+len(index)+len(value))
	tb = append(tb, str...)
	tb = append(tb, index...)
	tb = append(tb, value...)
	sig := crypto.Sign(key, tb)

	return &TemporaryBinding{
		Index:     index,
		Value:     value,
		Signature: sig,
	}
}
