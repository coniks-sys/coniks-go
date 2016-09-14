package merkletree

import "github.com/coniks-sys/coniks-go/crypto/sign"

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
