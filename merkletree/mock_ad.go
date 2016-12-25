package merkletree

import "encoding/gob"

func init() {
	gob.Register(&MockAd{})
}

type MockAd struct {
	Data string
}

func (t *MockAd) Serialize() []byte {
	return []byte(t.Data)
}
