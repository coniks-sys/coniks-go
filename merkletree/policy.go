package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type Timestamp uint64

// Policies is a summary of the directory's
// current security policies. This includes the public part
// of the VRF key used to generate private indices,
// the cryptographic algorithms in use, as well as
// the protocol version number.
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

// Serialize serializes the policies for signing the tree root.
// Default policies serialization includes the library version (see version.go),
// the cryptographic algorithms in use (i.e., the hashing algorithm),
// the epoch deadline and the public part of the VRF key.
func (p *Policies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(p.LibVersion)...)                       // lib Version
	bs = append(bs, []byte(p.HashID)...)                           // cryptographic algorithms in use
	bs = append(bs, utils.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, p.VrfPublicKey...)                             // vrf public key
	return bs
}
