package merkletree

type TemporaryBinding struct {
	index []byte
	value []byte
	sig   []byte
}

func (tb *TemporaryBinding) Index() []byte {
	return tb.index
}

func (tb *TemporaryBinding) Value() []byte {
	return tb.value
}

func (tb *TemporaryBinding) Signature() []byte {
	return tb.sig
}
