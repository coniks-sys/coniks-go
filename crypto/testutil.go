package crypto

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

// StaticVRF returns a static VRF private key for _tests_.
func StaticVRF(t *testing.T) vrf.PrivateKey {
	sk, err := vrf.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

// StaticSigning returns a static private signing key for _tests_.
func StaticSigning(t *testing.T) sign.PrivateKey {
	sk, err := sign.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		t.Fatal(err)
	}
	return sk
}
