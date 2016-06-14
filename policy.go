package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

type Policies interface {
	Serialize() []byte
}

type DefaultPolicies struct {
}

var _ Policies = (*DefaultPolicies)(nil)

func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)               // lib Version
	bs = append(bs, []byte(crypto.HashID)...)         // cryptographic algorithms in use
	bs = append(bs, util.LongToBytes(NextEpoch())...) // expected time of next epoch
	return bs
}
