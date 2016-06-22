package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
)

var signKey crypto.SigningKey

func init() {
	var err error
	signKey, err = crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
}

// 1st: counter = 1 (empty tree)
// 2nd: counter = 2 (key1)
// 3rd: counter = 3 (key1, key2)
// 4th: counter = 4 (key1, key2, key3) (latest STR)
func TestHistoryHashChain(t *testing.T) {
	key1 := "key"
	val1 := []byte("value")

	key2 := "key2"
	val2 := []byte("value2")

	key3 := "key3"
	val3 := []byte("value3")

	history, err := NewPAD(NewPolicies(2), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}

	if err := history.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}

	if err := history.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}

	if err := history.Set(key3, val3); err != nil {
		t.Fatal(err)
	}
	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 4; i++ {
		str := history.GetSTR(uint64(i))
		if str == nil {
			t.Fatal("Cannot get STR #", i)
		}

		if str.counter != uint64(i) {
			t.Fatal("Got invalid STR", "want", i, "got", str.counter)
		}
	}

	str := history.GetSTR(0)
	if str != nil {
		t.Error("Unexpected STR")
	}

	str = history.GetSTR(5)
	if str == nil {
		t.Error("Cannot get STR")
	}

	if str.counter != 4 {
		t.Error("Got invalid STR", "want", 4, "got", str.counter)
	}

	// lookup
	r, _ := history.LookUp(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	r, _ = history.LookUp(key2)
	if r == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(r.Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	r, _ = history.LookUp(key3)
	if r == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(r.Value(), val3) {
		t.Error(key3, "value mismatch")
	}

	r, _, err = history.LookUpInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	} else if r != nil {
		t.Error("Found unexpected key", key2, "in STR #", 2)
	}
	r, _, err = history.LookUpInEpoch(key2, 3)
	if err != nil {
		t.Error(err)
	} else if r == nil {
		t.Error("Cannot find key", key2, "in STR #", 3)
	}

	r, _, err = history.LookUpInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if r != nil {
		t.Error("Found unexpected key", key3, "in STR #", 3)
	}

	r, _, err = history.LookUpInEpoch(key3, 4)
	if err != nil {
		t.Error(err)
	} else if r == nil {
		t.Error("Cannot find key", key3, "in STR #", 4)
	}
}

func TestHashChainExceedsMaximumSize(t *testing.T) {
	var hashChainLimit int64 = 4

	history, err := NewPAD(NewPolicies(2), signKey, hashChainLimit)
	if err != nil {
		t.Fatal(err)
	}

	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}
	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}
	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}

	if len(history.snapshots) != int(hashChainLimit) {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit,
			"got", len(history.snapshots))
	}

	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}
	if len(history.snapshots) != int(hashChainLimit)/2+1 {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit/2+1,
			"got", len(history.snapshots))
	}

	if err := history.Update(nil); err != nil {
		t.Fatal(err)
	}
	if len(history.snapshots) != int(hashChainLimit)/2+2 {
		t.Error("Mismatch hash chain size",
			"expect", hashChainLimit/2+2,
			"got", len(history.snapshots))
	}
}
