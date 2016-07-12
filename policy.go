package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

type TimeStamp uint64

type Policies interface {
	EpochDeadline() TimeStamp
	Serialize() []byte
}

type DefaultPolicies struct {
	epochDeadline TimeStamp
}

var _ Policies = (*DefaultPolicies)(nil)

func NewPolicies(epDeadline TimeStamp) Policies {
	return &DefaultPolicies{
		epochDeadline: epDeadline,
	}
}

func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)                            // lib Version
	bs = append(bs, []byte(crypto.HashID)...)                      // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.epochDeadline))...) // epoch deadline
	return bs
}

func (p *DefaultPolicies) EpochDeadline() TimeStamp {
	return p.epochDeadline
}
