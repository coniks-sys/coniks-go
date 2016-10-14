package merkletree

import (
	"bytes"
	"testing"
)

func TestTB(t *testing.T) {
	key := "key"
	val := []byte("value")

	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, 3)
	if err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	tb, err := pad.TB(key, val)
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := pad.signKey.Public()
	if !ok {
		t.Fatal("Couldn't retrieve public-key.")
	}
	tbb := tb.Serialize(pad.latestSTR.Signature)
	if !pk.Verify(tbb, tb.Signature) {
		t.Fatal("Couldn't validate signature")
	}
	// verify VRF index of TB
	if !bytes.Equal(vrfPrivKey1.Compute([]byte(key)), tb.Index) {
		t.Error("VRF verification returns false")
	}

	// create next epoch and see if the TB is inserted as promised:
	pad.Update(nil)

	ap, err := pad.Lookup(key)

	// verify auth path
	if !ap.Verify(pad.LatestSTR().TreeHash) {
		t.Error("Proof of inclusion verification failed.")
	}

	if !tb.Verify(ap) {
		t.Error("Value wasn't inserted as promised")
	}
}
