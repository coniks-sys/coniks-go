package server

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/protocol"
)

// Policies contains a server's CONIKS policies configuration
// including paths to the VRF private key, the signing private
// key and the epoch deadline value in seconds.
type Policies struct {
	EpochDeadline protocol.Timestamp `toml:"epoch_deadline"`
	VRFKeyPath    string             `toml:"vrf_key_path"`
	SignKeyPath   string             `toml:"sign_key_path"` // it should be a part of policies, see #47
	vrfKey        vrf.PrivateKey
	signKey       sign.PrivateKey
}

// NewPolicies initializes a new Policies struct.
func NewPolicies(epDeadline protocol.Timestamp, vrfKeyPath,
	signKeyPath string, vrfKey vrf.PrivateKey,
	signKey sign.PrivateKey) *Policies {
	return &Policies{
		EpochDeadline: epDeadline,
		VRFKeyPath:    vrfKeyPath,
		SignKeyPath:   signKeyPath,
		vrfKey:        vrfKey,
		signKey:       signKey,
	}
}
