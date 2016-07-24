package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
)

var signKey crypto.SigningKey

func init() {
	var err error
	signKey, err = crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
}

// 1st: epoch = 0 (empty tree)
// 2nd: epoch = 1 (key1)
// 3rd: epoch = 2 (key1, key2)
// 4th: epoch = 3 (key1, key2, key3) (latest STR)
func TestPADHashChain(t *testing.T) {
	key1 := "key"
	val1 := []byte("value")

	key2 := "key2"
	val2 := []byte("value2")

	key3 := "key3"
	val3 := []byte("value3")

	pad, err := NewPAD(NewPolicies(2), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}

	if err := pad.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	if err := pad.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	if err := pad.Set(key3, val3); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	for i := 0; i < 4; i++ {
		str := pad.GetSTR(uint64(i))
		if str == nil {
			t.Fatal("Cannot get STR #", i)
		}

		if str.epoch != uint64(i) {
			t.Fatal("Got invalid STR", "want", i, "got", str.epoch)
		}
	}

	str := pad.GetSTR(5)
	if str == nil {
		t.Error("Cannot get STR")
	}

	if str.epoch != 3 {
		t.Error("Got invalid STR", "want", 3, "got", str.epoch)
	}

	// lookup
	ap := pad.Lookup(key1)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(ap.Leaf().Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	ap = pad.Lookup(key2)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(ap.Leaf().Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	ap = pad.Lookup(key3)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(ap.Leaf().Value(), val3) {
		t.Error(key3, "value mismatch")
	}

	ap, err = pad.LookupInEpoch(key2, 1)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf().Value() != nil {
		t.Error("Found unexpected key", key2, "in STR #", 1)
	}
	ap, err = pad.LookupInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf().Value() == nil {
		t.Error("Cannot find key", key2, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf().Value() != nil {
		t.Error("Found unexpected key", key3, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf().Value() == nil {
		t.Error("Cannot find key", key3, "in STR #", 3)
	}
}

func TestHashChainExceedsMaximumSize(t *testing.T) {
	var hashChainLimit uint64 = 4

	pad, err := NewPAD(NewPolicies(2), signKey, hashChainLimit)
	if err != nil {
		t.Fatal(err)
	}

	pad.Update(nil)
	pad.Update(nil)
	pad.Update(nil)

	if len(pad.snapshots) != int(hashChainLimit) {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit,
			"got", len(pad.snapshots))
	}

	pad.Update(nil)
	if len(pad.snapshots) != int(hashChainLimit)/2+1 {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit/2+1,
			"got", len(pad.snapshots))
	}

	pad.Update(nil)
	if len(pad.snapshots) != int(hashChainLimit)/2+2 {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit/2+2,
			"got", len(pad.snapshots))
	}
}
