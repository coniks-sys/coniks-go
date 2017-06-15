package directory

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

// TODO: refactor the function signature after resolving #47

// NewTestDirectory creates a ConiksDirectory used for testing server-side
// CONIKS operations.
func NewTestDirectory(t *testing.T, useTBs bool) (
	*ConiksDirectory, sign.PublicKey) {

	// FIXME: NewTestDirectory should use a fixed VRF and Signing keys.
	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := signKey.Public()
	// epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey,
	// signKey sign.PrivateKey, dirSize uint64, useTBs bool
	d := New(1, vrfKey, signKey, 10, useTBs)
	return d, pk
}
