package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type TimeStamp uint64

type Policies interface {
	EpDeadline() TimeStamp
	Serialize() []byte
	vrfPrivate() vrf.PrivateKey
}

type ConiksPolicies struct {
	LibVersion    string
	HashID        string
	vrfPrivateKey vrf.PrivateKey
	VrfPubKey     []byte
	EpochDeadline TimeStamp
}

var _ Policies = (*ConiksPolicies)(nil)

func NewPolicies(epDeadline TimeStamp, vrfPrivKey vrf.PrivateKey) Policies {
	vrfPublicKey, ok := vrfPrivKey.Public()
	if !ok {
		panic(vrf.ErrorGetPubKey)
	}
	return &ConiksPolicies{
		LibVersion:    Version,
		HashID:        crypto.HashID,
		vrfPrivateKey: vrfPrivKey,
		VrfPubKey:     vrfPublicKey,
		EpochDeadline: epDeadline,
	}
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline, vrf public key]
func (p *ConiksPolicies) Serialize() []byte {
	vrfPublicKey, ok := p.vrfPrivateKey.Public()
	if !ok {
		panic(vrf.ErrorGetPubKey)
	}
	var bs []byte
	bs = append(bs, []byte(p.LibVersion)...)                       // lib Version
	bs = append(bs, []byte(p.HashID)...)                           // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, vrfPublicKey...)                               // vrf public key
	return bs
}

func (p *ConiksPolicies) vrfPrivate() vrf.PrivateKey {
	return p.vrfPrivateKey
}

func (p *ConiksPolicies) EpDeadline() TimeStamp {
	return p.EpochDeadline
}
