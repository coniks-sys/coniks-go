package merkletree

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
)

func TestVerifyHashChain(t *testing.T) {
	var N uint64 = 100

	pad, err := NewPAD(TestAd{"abc"}, crypto.StaticSigning(t), crypto.StaticVRF(t), N)
	if err != nil {
		t.Fatal(err)
	}

	savedSTR := pad.LatestSTR()
	pk, _ := pad.signKey.Public()

	for i := uint64(1); i < N; i++ {
		key := keyPrefix + string(i)
		value := append(valuePrefix, byte(i))
		if err := pad.Set(key, value); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil)

		// verify STR signature
		str := pad.LatestSTR()
		if !pk.Verify(str.Serialize(), str.Signature) {
			t.Fatal("Invalid STR signature at epoch", i)
		}

		// verify hash chain
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Spurious STR at epoch", i)
		}
		savedSTR = str
	}
}
