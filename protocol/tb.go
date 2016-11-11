package protocol

type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}
