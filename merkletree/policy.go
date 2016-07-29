package merkletree

import (
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

type TimeStamp uint64

type Policies interface {
	Iterate() map[string][]byte
	Serialize() []byte
	vrfPrivate() *[vrf.SecretKeySize]byte
}

type ConiksPolicies struct {
	LibVersion    string
	HashID        string
	vrfPrivateKey *[vrf.SecretKeySize]byte
	EpochDeadline TimeStamp
}

var _ Policies = (*ConiksPolicies)(nil)

func NewPolicies(epDeadline TimeStamp, vrfPrivKey *[vrf.SecretKeySize]byte) Policies {
	return &ConiksPolicies{
		LibVersion:    Version,
		HashID:        crypto.HashID,
		vrfPrivateKey: vrfPrivKey,
		EpochDeadline: epDeadline,
	}
}

// Iterate returns a map of exported fields' name to their values
func (p *ConiksPolicies) Iterate() map[string][]byte {
	s := reflect.ValueOf(p).Elem()
	typeOfT := s.Type()
	fields := make(map[string][]byte, s.NumField())
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		if !f.CanInterface() {
			continue
		}
		switch f.Interface().(type) {
		case string:
			fields[typeOfT.Field(i).Name] = []byte(f.Interface().(string))
		case TimeStamp:
			fields[typeOfT.Field(i).Name] = util.ULongToBytes(uint64(f.Interface().(TimeStamp)))
		}
	}
	fields["VRFPublic"] = vrf.Public(p.vrfPrivateKey)
	return fields
}

// Serialize encodes the policy to a byte array with the following format:
// [lib version, cryptographic algorithm in use, epoch deadline, vrf public key]
func (p *ConiksPolicies) Serialize() []byte {
	var bs []byte
	bs = append(bs, []byte(p.LibVersion)...)                       // lib Version
	bs = append(bs, []byte(p.HashID)...)                           // cryptographic algorithms in use
	bs = append(bs, util.ULongToBytes(uint64(p.EpochDeadline))...) // epoch deadline
	bs = append(bs, vrf.Public(p.vrfPrivateKey)...)                // vrf public key
	return bs
}

func (p *ConiksPolicies) vrfPrivate() *[vrf.SecretKeySize]byte {
	return p.vrfPrivateKey
}
