package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type TimeStamp uint64

type Policies interface {
	EpochDeadline() TimeStamp
	Serialize() []byte
	vrfPrivate() *[vrf.SecretKeySize]byte
}

type DefaultPolicies struct {
	vrfPrivateKey *[vrf.SecretKeySize]byte
	epochDeadline TimeStamp
}

var _ Policies = (*DefaultPolicies)(nil)

func NewPolicies(epDeadline TimeStamp, vrfPrivKey *[vrf.SecretKeySize]byte) Policies {
	return &DefaultPolicies{
		epochDeadline: epDeadline,
		vrfPrivateKey: vrfPrivKey,
	}
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline]
func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)                            // lib Version
	bs = append(bs, []byte(crypto.HashID)...)                      // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.epochDeadline))...) // epoch deadline
	bs = append(bs, vrf.Public(p.vrfPrivateKey)...)                // vrf public key
	return bs
}

func (p *DefaultPolicies) vrfPrivate() *[vrf.SecretKeySize]byte {
	return p.vrfPrivateKey
}

func (p *DefaultPolicies) EpochDeadline() TimeStamp {
	return p.epochDeadline
}
