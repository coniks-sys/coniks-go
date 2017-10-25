package directory

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

var staticSigningKey = crypto.NewStaticTestSigningKey()
var staticVRFKey = crypto.NewStaticTestVRFKey()

// NewTestDirectory creates a ConiksDirectory used for testing server-side
// CONIKS operations.
func NewTestDirectory(t *testing.T) *ConiksDirectory {
	vrfKey := staticVRFKey
	signKey := staticSigningKey
	d := New(1, vrfKey, signKey, 10, true)
	d.pad = merkletree.StaticPAD(t, d.policies)
	return d
}
