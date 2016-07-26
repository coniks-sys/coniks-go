package merkletree

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

type TimeStamp uint64

type Policies interface {
	EpochDeadline() TimeStamp
	Serialize() []byte
	vrfPrivate() *[vrf.SecretKeySize]byte

	// storage interface
	StoreToKV(uint64, kv.Batch)
	LoadFromKV(kv.DB, uint64) error
	serializeKvKey(uint64) []byte
}

type DefaultPolicies struct {
	LibVersion    string
	HashID        string
	vrfPrivateKey *[vrf.SecretKeySize]byte
	epochDeadline TimeStamp
}

var _ Policies = (*DefaultPolicies)(nil)

func NewPolicies(epDeadline TimeStamp, vrfPrivKey *[vrf.SecretKeySize]byte) Policies {
	return &DefaultPolicies{
		LibVersion:    Version,
		HashID:        crypto.HashID,
		epochDeadline: epDeadline,
		vrfPrivateKey: vrfPrivKey,
	}
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline]
func (p *DefaultPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(p.LibVersion)...)                       // lib Version
	bs = append(bs, []byte(p.HashID)...)                           // cryptographic algorithms in use
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
