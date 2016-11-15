package protocol

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
	VrfPublicKey  vrf.PublicKey
	EpochDeadline Timestamp
	LibVersion    string
	HashID        string
}

func NewPolicies(epDeadline Timestamp, vrfPublicKey vrf.PublicKey) *Policies {
	return &Policies{
		VrfPublicKey:  vrfPublicKey,
		EpochDeadline: epDeadline,
		LibVersion:    Version,
		HashID:        crypto.HashID,
	}
}

// Serialize serializes the policies for signing the tree root.
// Default policies serialization includes the library version (see version.go),
// the cryptographic algorithms in use (i.e., the hashing algorithm),
// the epoch deadline and the public part of the VRF key.
func (p *Policies) Serialize() []byte {
	var bs []byte
	bs = append(bs, p.VrfPublicKey...)                              // vrf public key
	bs = append(bs, utils.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, []byte(p.LibVersion)...)                        // lib Version
	bs = append(bs, []byte(p.HashID)...)                            // cryptographic algorithms in use
	return bs
}

// FIXME: I'm just being lazy :(
func ParsePubKey(policies []byte) vrf.PublicKey {
	return vrf.PublicKey(policies[0:vrf.PublicKeySize])
}

// FIXME: Same.
func ParseEpochDeadline(policies []byte) Timestamp {
	return Timestamp(utils.BytesToULong(policies[vrf.PublicKeySize:]))
}
