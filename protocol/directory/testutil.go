package directory

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// NewTestDirectory creates a ConiksDirectory used for testing server-side
// CONIKS operations.
func NewTestDirectory(t *testing.T) *ConiksDirectory {
	vrfKey := crypto.NewStaticTestVRFKey()
	signKey := crypto.NewStaticTestSigningKey()
	d := New(1, vrfKey, signKey, 10, true)
	d.pad = merkletree.StaticPAD(t, d.policies)
	return d
}
