package merkletree

import "github.com/coniks-sys/libmerkleprefixtree-go/crypto"

type Policies interface {
	Serialize() []byte
}

type DefaultPolicies struct {
}

var _ Policies = (*DefaultPolicies)(nil)

func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)       // lib Version
	bs = append(bs, []byte(crypto.HashID)...) // cryptographic algorithms in use
	return bs
}
