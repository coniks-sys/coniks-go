package merkletree

import (
	"bytes"
	"testing"

	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/coniks-sys/coniks-go/crypto/sign"
)

var signKey sign.PrivateKey

func init() {
	var err error
	signKey, err = sign.GenerateKey(nil)
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
		if !bytes.Equal(str.TreeHash, treeHashes[uint64(i)]) {
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
	ap, _ := pad.LookupInLatestEpoch(key1)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(ap.Leaf.Value, val1) {
		t.Error(key1, "value mismatch")
	}

	ap, _ = pad.LookupInLatestEpoch(key2)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(ap.Leaf.Value, val2) {
		t.Error(key2, "value mismatch")
	}

	ap, _ = pad.LookupInLatestEpoch(key3)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(ap.Leaf.Value, val3) {
		t.Error(key3, "value mismatch")
	}

	ap, err = pad.LookupInEpoch(key2, 1)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value != nil {
		t.Error("Found unexpected key", key2, "in STR #", 1)
	}
	ap, err = pad.LookupInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value == nil {
		t.Error("Cannot find key", key2, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 2)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value != nil {
		t.Error("Found unexpected key", key3, "in STR #", 2)
	}

	ap, err = pad.LookupInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value == nil {
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

	ap, _ := pad.LookupInLatestEpoch(key1)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
	}
	if !bytes.Equal(ap.Leaf.Value, val1) {
		t.Error(key1, "value mismatch")
	}

	ap, _ = pad.LookupInLatestEpoch(key2)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key2)
	}
	if !bytes.Equal(ap.Leaf.Value, val2) {
		t.Error(key2, "value mismatch")
	}

	ap, err = pad.LookupInEpoch(key1, 1)
	if err != nil {
		t.Error(err)
	} else if !bytes.Equal(ap.Leaf.Value, val1) {
		t.Error(key1, "value mismatch")
	}
	ap, err = pad.LookupInEpoch(key2, 2)
	if err != nil {
		t.Error(err)
	}
	ap, err = pad.LookupInEpoch(key3, 3)
	if err != nil {
		t.Error(err)
	} else if ap.Leaf.Value == nil {
		t.Error("Cannot find key", key3, "in STR #", 3)
	} else if !bytes.Equal(ap.Leaf.Value, val3) {
		t.Error(key3, "value mismatch")
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

// TODO move the following to some (internal?) testutils package
type testErrorRandReader struct{}

func (er testErrorRandReader) Read([]byte) (int, error) {
	return 0, errors.New("Not enough entropy!")
}

func mockRandReadWithErroringReader() (orig io.Reader) {
	orig = rand.Reader
	rand.Reader = testErrorRandReader{}
	return
}

func unMockRandReader(orig io.Reader) {
	rand.Reader = orig
}

func TestNewPADErrorWhileCreatingTree(t *testing.T) {
	origRand := mockRandReadWithErroringReader()
	defer unMockRandReader(origRand)

	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, 3)
	if err == nil || pad != nil {
		t.Fatal("NewPad should return an error in case the tree creation failed")
	}
}

func BenchmarkCreateLargePAD(b *testing.B) {
	snapLen := uint64(10)
	keyPrefix := "key"
	valuePrefix := []byte("value")

	// total number of entries in tree:
	NumEntries := uint64(1000000)
	// tree.Clone and update STR every:
	noUpdate := uint64(NumEntries + 1)

	b.ResetTimer()
	// benchmark creating a large tree (don't Update tree)
	for n := 0; n < b.N; n++ {
		_, err := createPad(NumEntries, keyPrefix, valuePrefix, snapLen,
			noUpdate)
		if err != nil {
			b.Fatal(err)
		}
	}
}

//
// Benchmarks which can be used produce data similar to Figure 7. in Section 5.
//
func BenchmarkPADUpdate100K(b *testing.B) { benchPADUpdate(b, 100000) }
func BenchmarkPADUpdate500K(b *testing.B) { benchPADUpdate(b, 500000) }

// make sure you have enough memory/cpu power if you want to run the benchmarks
// below; also give the benchmarks enough time to finish using the -timeout flag
func BenchmarkPADUpdate1M(b *testing.B)   { benchPADUpdate(b, 1000000) }
func BenchmarkPADUpdate2_5M(b *testing.B) { benchPADUpdate(b, 2500000) }
func BenchmarkPADUpdate5M(b *testing.B)   { benchPADUpdate(b, 5000000) }
func BenchmarkPADUpdate7_5M(b *testing.B) { benchPADUpdate(b, 7500000) }
func BenchmarkPADUpdate10M(b *testing.B)  { benchPADUpdate(b, 10000000) }

func benchPADUpdate(b *testing.B, entries uint64) {
	keyPrefix := "key"
	valuePrefix := []byte("value")
	snapLen := uint64(10)
	noUpdate := uint64(entries + 1)
	pad, err := createPad(uint64(entries), keyPrefix, valuePrefix, snapLen, noUpdate)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pad.Update(nil)
	}
}

//
// END Benchmarks for Figure 7. in Section 5
//

func BenchmarkPADLookUpFrom10K(b *testing.B)  { benchPADLookup(b, 10000) }
func BenchmarkPADLookUpFrom50K(b *testing.B)  { benchPADLookup(b, 50000) }
func BenchmarkPADLookUpFrom100K(b *testing.B) { benchPADLookup(b, 100000) }
func BenchmarkPADLookUpFrom500K(b *testing.B) { benchPADLookup(b, 500000) }
func BenchmarkPADLookUpFrom1M(b *testing.B)   { benchPADLookup(b, 1000000) }
func BenchmarkPADLookUpFrom5M(b *testing.B)   { benchPADLookup(b, 5000000) }
func BenchmarkPADLookUpFrom10M(b *testing.B)  { benchPADLookup(b, 10000000) }

func benchPADLookup(b *testing.B, entries uint64) {
	snapLen := uint64(10)
	keyPrefix := "key"
	valuePrefix := []byte("value")
	updateOnce := uint64(entries - 1)
	pad, err := createPad(entries, keyPrefix, valuePrefix, snapLen,
		updateOnce)
	if err != nil {
		b.Fatal(err)
	}
	// ignore the tree creation:
	b.ResetTimer()
	//fmt.Println("Done creating large pad/tree.")

	// measure LookUps in large tree (with NumEntries leafs)
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		var key string
		if n < int(entries) {
			key = keyPrefix + string(n)
		} else {
			key = keyPrefix + string(n%int(entries))
		}
		b.StartTimer()
		_, err := pad.LookupInLatestEpoch(key)
		if err != nil {
			b.Fatalf("Coudldn't lookup key=%s", key)
		}
	}
}

// creates a PAD containing a tree with N entries (+ potential emptyLeafNodes)
// each key value pair has the form (keyPrefix+string(i), valuePrefix+string(i))
// for i = 0,...,N
// The STR will get updated every epoch defined by every multiple of
// `updateEvery`. If `updateEvery > N` createPAD won't update the STR.
func createPad(N uint64, keyPrefix string, valuePrefix []byte, snapLen uint64,
	updateEvery uint64) (*PAD, error) {
	pad, err := NewPAD(NewPolicies(3, vrfPrivKey1), signKey, snapLen)
	if err != nil {
		return nil, err
	}

	for i := uint64(0); i < N; i++ {
		key := keyPrefix + string(i)
		value := append(valuePrefix, byte(i))
		if err := pad.Set(key, value); err != nil {
			return nil, fmt.Errorf("Couldn't set key=%s and value=%s. Error: %v",
				key, value, err)
		}
		if i != 0 && (i%updateEvery == 0) {
			pad.Update(nil)
		}
	}
	return pad, nil
}
