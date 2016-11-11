package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type Timestamp uint64

type Policies struct {
	LibVersion    string
	HashID        string
	vrfPrivateKey vrf.PrivateKey
	VrfPublicKey  vrf.PublicKey
	EpochDeadline Timestamp
}

func NewPolicies(epDeadline Timestamp, vrfPrivKey vrf.PrivateKey) *Policies {
	vrfPublicKey, ok := vrfPrivKey.Public()
	if !ok {
		panic(vrf.ErrorGetPubKey)
	}
	return &Policies{
		LibVersion:    Version,
		HashID:        crypto.HashID,
		vrfPrivateKey: vrfPrivKey,
		VrfPublicKey:  vrfPublicKey,
		EpochDeadline: epDeadline,
	}
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline, vrf public key]
func (p *Policies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(p.LibVersion)...)                       // lib Version
	bs = append(bs, []byte(p.HashID)...)                           // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, p.VrfPublicKey...)                             // vrf public key
	return bs
}
