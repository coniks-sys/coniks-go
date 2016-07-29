package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/coniks-sys/coniks-go/crypto"
	"io"
)

var signKey sign.PrivateKey

func init() {
	var err error
	signKey, err = sign.GenerateKey()
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

	treeHashes := make(map[uint64][]byte)

	pad, err := NewPAD(NewPolicies(2, vrfPrivKey1), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	treeHashes[0] = append([]byte{}, pad.tree.hash...)

	if err := pad.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)
	treeHashes[1] = append([]byte{}, pad.tree.hash...)

	if err := pad.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)
	treeHashes[2] = append([]byte{}, pad.tree.hash...)

	if err := pad.Set(key3, val3); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)
	treeHashes[3] = append([]byte{}, pad.tree.hash...)

	for i := 0; i < 4; i++ {
		str := pad.GetSTR(uint64(i))
		if str == nil {
			t.Fatal("Cannot get STR #", i)
		}
		if !bytes.Equal(str.Root(), treeHashes[uint64(i)]) {
			t.Fatal("Malformed PAD Update")
		}

		if str.Epoch != uint64(i) {
			t.Fatal("Got invalid STR", "want", i, "got", str.Epoch)
		}
	}

	str := pad.GetSTR(5)
	if str == nil {
		t.Error("Cannot get STR")
	}

	if str.Epoch != 3 {
		t.Error("Got invalid STR", "want", 3, "got", str.Epoch)
	}

	// lookup
	ap, _ := pad.Lookup(key1)
	if ap.Leaf.Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(ap.Leaf.Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	ap, _ = pad.Lookup(key2)
	if ap.Leaf.Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(ap.Leaf.Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	ap, _ = pad.Lookup(key3)
	if ap.Leaf.Value() == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(ap.Leaf.Value(), val3) {
		t.Error(key3, "value mismatch")
	}

	ap, err = pad.LookupInEpoch(key2, 1)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value() != nil {
		t.Error("Found unexpected key", key2, "in STR #", 1)
	}
	ap, err = pad.LookupInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value() == nil {
		t.Error("Cannot find key", key2, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value() != nil {
		t.Error("Found unexpected key", key3, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value() == nil {
		t.Error("Cannot find key", key3, "in STR #", 3)
	}
}

func TestHashChainExceedsMaximumSize(t *testing.T) {
	var hashChainLimit uint64 = 4

	pad, err := NewPAD(NewPolicies(2, vrfPrivKey1), signKey, hashChainLimit)
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

func TestPoliciesChange(t *testing.T) {
	key1 := "key"
	val1 := []byte("value")

	key2 := "key2"
	val2 := []byte("value2")

	key3 := "key3"
	val3 := []byte("value3")

	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}

	if err := pad.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	// key change between epoch 1 and 2:
	pad.Update(NewPolicies(3, vrfPrivKey2))

	if err := pad.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	if err := pad.Set(key3, val3); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	ap, _ := pad.Lookup(key1)
	if ap.Leaf.Value() == nil {
		t.Error("Cannot find key:", key1)
	}
	if !bytes.Equal(ap.Leaf.Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	ap, _ = pad.Lookup(key2)
	if ap.Leaf.Value() == nil {
		t.Error("Cannot find key:", key2)
	}
	if !bytes.Equal(ap.Leaf.Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	ap, err = pad.LookupInEpoch(key1, 1)
	if err != nil {
		t.Error(err)
	} else if !bytes.Equal(ap.Leaf.Value(), val1) {
		t.Error(key1, "value mismatch")
	}
	ap, err = pad.LookupInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	}
	ap, err = pad.LookupInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value() == nil {
		t.Error("Cannot find key", key3, "in STR #", 3)
	} else if !bytes.Equal(ap.Leaf.Value(), val3) {
		t.Error(key3, "value mismatch")
	}
}

func TestTB(t *testing.T) {
	key1 := "key"
	val1 := []byte("value")

	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, 3)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := pad.TB(key1, val1)
	if err != nil {
		t.Fatal(err)
	}

	// TODO shouldn't there be a serialize function?
	tbb := pad.latestSTR.Signature
	tbb = append(tbb, tb.Index...)
	tbb = append(tbb, tb.Value...)

	// TODO use SigningKeyToPublic from crypto as soon as it is merged:
	// pub := ed25519.PrivateKey(pad.key[:]).Public().(crypto.SigningKey)
	// TODO Verify shouldn't use private key (related to above comment)
	if !crypto.Verify(pad.key, tbb, tb.Signature) {
		t.Fatal("Couldn't validate signature")
	}
	// create next epoch and see if the TB is inserted as promised:
	pad.Update(nil)

	ap, err := pad.Lookup(key1)
	if !bytes.Equal(ap.LookupIndex, tb.Index) || !bytes.Equal(ap.Leaf.Value(), tb.Value) {
		t.Error("Value wasn't inserted as promised")
	}
}

func TestNewPADMissingPolicies(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected NewPAD to panic if policies are missing.")
		}
	}()
	if _, err := NewPAD(nil, signKey, 10); err != nil {
		t.Fatal("Expected NewPAD to panic but got error.")
	}
}

// TODO move this to helper "mockRandReader" or sth like that; and provide a
// an equivalent function to reset the original rand.Reader
type testErrorRandReader struct{}

func (er testErrorRandReader) Read([]byte) (int, error) {
	return 0, errors.New("Not enough entropy!")
}

func TestNewPADErrorWhileCreatingTree(t *testing.T) {
	origRand := rand.Reader
	rand.Reader = testErrorRandReader{}
	defer func(orig io.Reader) {
		rand.Reader = orig
	}(origRand)
	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, 3)
	if err == nil || pad != nil {
		t.Fatal("NewPad should return an error in case the tree creation failed")
	}
}

func BenchmarkCreateLargePAD(b *testing.B) {
	snapLen := uint64(10)
	keyPrefix := "key"
	valuePrefix := []byte("value")

	NumEntries := 10000
	b.ResetTimer()
	// benchmark creating a large tree:
	for n := 0; n < b.N && n < NumEntries; n++ {
		_, err := createPad(NumEntries, keyPrefix, valuePrefix, snapLen,
			false)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func BenchmarkLookUpFromLargeDirectory(b *testing.B) {
	snapLen := uint64(10)
	keyPrefix := "key"
	valuePrefix := []byte("value")

	NumEntries := 100000
	pad, err := createPad(NumEntries, keyPrefix, valuePrefix,
		snapLen, false)
	if err != nil {
		b.Fatal(err)
	}
	// ignore the tree creation:
	b.ResetTimer()
	fmt.Println("Done creating large pad/tree.")

	// measure LookUps in large tree (with NumEntries leafs)
	for n := 0; n < b.N && n < NumEntries; n++ {
		key := keyPrefix + string(n)
		_, err := pad.Lookup(key)
		if err != nil {
			b.Fatalf("Coudldn't lookup key=%s", key)
		}
	}
}

// creates a PAD containing a tree with N entries (+ potential emptyLeafNodes)
// each key value pair has the form (keyPrefix+string(i), valuePrefix+string(i))
// for i = 0,...,N
// After each inserted value the STR gets updated
func createPad(N int, keyPrefix string, valuePrefix []byte, snapLen uint64,
	updateAfterEachSet bool) (*PAD, error) {
	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, snapLen)
	if err != nil {
		return nil, err
	}

	for i := 0; i < N; i++ {
		key := keyPrefix + string(i)
		value := append(valuePrefix, byte(i))
		if err := pad.Set(key, value); err != nil {
			return nil, fmt.Errorf("Couldn't set key=%s and value=%s. Error: %v",
				key, value, err)
		}
		if updateAfterEachSet {
			pad.Update(nil)
		}
	}
	if !updateAfterEachSet {
		pad.Update(nil)
	}
	return pad, nil
}
