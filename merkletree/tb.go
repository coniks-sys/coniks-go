package merkletree

type TemporaryBinding struct {
	str   []byte
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

func (tb *TemporaryBinding) STR() []byte {
	return tb.str
}
