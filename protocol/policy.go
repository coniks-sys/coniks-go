package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/utils"
)

type Timestamp uint64

// Policies is a summary of the directory's
// current security policies. This includes the public part
// of the VRF key used to generate private indices,
// the cryptographic algorithms in use, as well as
// the protocol version number.
type Policies struct {
	Version       string
	HashID        string
	VrfPublicKey  vrf.PublicKey
	EpochDeadline Timestamp
}

var _ merkletree.AssocData = (*Policies)(nil)

func NewPolicies(epDeadline Timestamp, vrfPublicKey vrf.PublicKey) *Policies {
	return &Policies{
		Version:       Version,
		HashID:        crypto.HashID,
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
	bs = append(bs, []byte(p.Version)...)                           // protocol version
	bs = append(bs, []byte(p.HashID)...)                            // cryptographic algorithms in use
	bs = append(bs, p.VrfPublicKey...)                              // vrf public key
	bs = append(bs, utils.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	return bs
}

// GetPolicies returns the set of policies hashed in the STR.
func GetPolicies(str *merkletree.SignedTreeRoot) *Policies {
	return str.Ad.(*Policies)
}
