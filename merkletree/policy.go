package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type TimeStamp uint64

type Policies interface {
	Serialize() []byte
	vrfPrivate() *[vrf.SecretKeySize]byte
}

type ConiksPolicies struct {
	vrfPrivateKey *[vrf.SecretKeySize]byte
	EpochDeadline TimeStamp
}

var _ Policies = (*ConiksPolicies)(nil)

func NewPolicies(epDeadline TimeStamp, vrfPrivKey *[vrf.SecretKeySize]byte) Policies {
	return &ConiksPolicies{
		EpochDeadline: epDeadline,
		vrfPrivateKey: vrfPrivKey,
	}
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline]
func (p *ConiksPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(Version)...)                            // lib Version
	bs = append(bs, []byte(crypto.HashID)...)                      // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, vrf.Public(p.vrfPrivateKey)...)                // vrf public key
	return bs
}

func (p *ConiksPolicies) vrfPrivate() *[vrf.SecretKeySize]byte {
	return p.vrfPrivateKey
}
