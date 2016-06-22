package merkletree

import (
	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

type Epoch int64

type Policies interface {
	EpochInterval() Epoch
	Serialize() []byte
}

type DefaultPolicies struct {
	epochInterval Epoch
}

var _ Policies = (*DefaultPolicies)(nil)

func NewPolicies(epInterval Epoch) Policies {
	return &DefaultPolicies{
		epochInterval: epInterval,
	}
}

func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)                          // lib Version
	bs = append(bs, []byte(crypto.HashID)...)                    // cryptographic algorithms in use
	bs = append(bs, util.LongToBytes(int64(p.epochInterval))...) // epoch interval
	return bs
}

func (p *DefaultPolicies) EpochInterval() Epoch {
	return p.epochInterval
}
