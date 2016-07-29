package merkletree

import "github.com/coniks-sys/coniks-go/crypto"

type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

func NewTB(key crypto.SigningKey, strSig, index, value []byte) *TemporaryBinding {
	tb := &TemporaryBinding{
		Index: index,
		Value: value,
	}
	tbPreSig := tb.Serialize(strSig)
	tb.Signature = key.Sign(tbPreSig)
	return tb
}

func innerTBSerialize(strSig, index, value []byte) []byte {
	var tbBytes []byte
	tbBytes = append(tbBytes, strSig...)
	tbBytes = append(tbBytes, index...)
	tbBytes = append(tbBytes, value...)
	return tbBytes
}

func (tb *TemporaryBinding) Serialize(strSig []byte) []byte {
	return innerTBSerialize(strSig, tb.Index, tb.Value)
}

func VerifyTB(pk crypto.VerifKey, strSig, index, value, tbSig []byte) bool {
	tbBytes := innerTBSerialize(strSig, index, value)
	return pk.Verify(tbBytes, tbSig)
}
