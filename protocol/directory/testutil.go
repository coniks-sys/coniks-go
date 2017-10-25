package directory

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// NewTestDirectory creates a ConiksDirectory used for testing server-side
// CONIKS operations.
func NewTestDirectory(t *testing.T) *ConiksDirectory {
	vrfKey := crypto.StaticVRF(t)
	signKey := crypto.StaticSigning(t)
	d := New(1, vrfKey, signKey, 10, true)
	d.pad = merkletree.StaticPAD(t, d.policies)
	return d
}
