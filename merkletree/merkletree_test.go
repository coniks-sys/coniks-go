package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
	"golang.org/x/crypto/sha3"
)

// TODO: When #178 is merged, 3 tests below should be removed.
func TestOneEntry(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	var commit [32]byte
	var expect [32]byte

	key := "key"
	val := []byte("value")
	index := crypto.StaticVRF(t).Compute([]byte(key))
	if err := m.Set(index, key, val); err != nil {
		t.Fatal(err)
	}
	m.recomputeHash()

	// Check empty node hash
	h := sha3.NewShake128()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(m.nonce)
	h.Write(utils.ToBytes([]bool{true}))
	h.Write(utils.UInt32ToBytes(1))
	h.Read(expect[:])
	if !bytes.Equal(m.root.rightHash, expect[:]) {
		t.Error("Wrong righ hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	r := m.Get(index)
	if r.Leaf.Value == nil {
		t.Error("Cannot find value of key:", key)
		return
	}
	v := r.Leaf.Value
	if !bytes.Equal(v, val) {
		t.Errorf("Value mismatch %v / %v", v, val)
	}

	// Check leaf node hash
	h.Reset()
	h.Write(r.Leaf.Commitment.Salt)
	h.Write([]byte(key))
	h.Write(val)
	h.Read(commit[:])

	h.Reset()
	h.Write([]byte{LeafIdentifier})
	h.Write(m.nonce)
	h.Write(index)
	h.Write(utils.UInt32ToBytes(1))
	h.Write(commit[:])
	h.Read(expect[:])

	if !bytes.Equal(m.root.leftHash, expect[:]) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	r = m.Get([]byte("abc"))
	if r.Leaf.Value != nil {
		t.Error("Invalid look-up operation:", key)
		return
	}
}

func TestTwoEntries(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := crypto.StaticVRF(t).Compute([]byte(key1))
	val1 := []byte("value1")
	key2 := "key2"
	index2 := crypto.StaticVRF(t).Compute([]byte(key2))
	val2 := []byte("value2")

	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(index2, key2, val2); err != nil {
		t.Fatal(err)
	}

	ap1 := m.Get(index1)
	if ap1.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	ap2 := m.Get(index2)
	if ap2.Leaf.Value == nil {
		t.Error("Cannot find key:", key2)
		return
	}

	if !bytes.Equal(ap1.Leaf.Value, []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(ap2.Leaf.Value, []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
}

func TestThreeEntries(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := crypto.StaticVRF(t).Compute([]byte(key1))
	val1 := []byte("value1")
	key2 := "key2"
	index2 := crypto.StaticVRF(t).Compute([]byte(key2))
	val2 := []byte("value2")
	key3 := "key3"
	index3 := crypto.StaticVRF(t).Compute([]byte(key3))
	val3 := []byte("value3")

	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(index2, key2, val2); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(index3, key3, val3); err != nil {
		t.Fatal(err)
	}

	ap1 := m.Get(index1)
	if ap1.Leaf.Value == nil {
		t.Error("Cannot find key:", index1)
		return
	}
	ap2 := m.Get(index2)
	if ap2.Leaf.Value == nil {
		t.Error("Cannot find key:", index2)
		return
	}
	ap3 := m.Get(index3)
	if ap3.Leaf.Value == nil {
		t.Error("Cannot find key:", index3)
		return
	}
	/*
		// since the first bit of ap2 index is false and the one of ap1 & ap3 are true
		if ap2.Leaf.Level() != 1 {
			t.Error("Malformed tree insertion")
		}

		// since n1 and n3 share first 2 bits
		if ap1.Leaf.Level() != 3 {
			t.Error("Malformed tree insertion")
		}
		if ap3.Leaf.Level() != 3 {
			t.Error("Malformed tree insertion")
		}
	*/

	if !bytes.Equal(ap1.Leaf.Value, []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(ap2.Leaf.Value, []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
	if !bytes.Equal(ap3.Leaf.Value, []byte("value3")) {
		t.Error(key3, "value mismatch")
	}
}

func TestInsertExistedKey(t *testing.T) {
	m := newTestTree(t)

	key1 := "key"
	index1 := crypto.StaticVRF(t).Compute([]byte(key1))
	val1 := append([]byte(nil), "value"...)

	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}

	val2 := []byte("new value")
	if err := m.Set(index1, key1, val2); err != nil {
		t.Fatal(err)
	}

	ap := m.Get(index1)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(ap.Leaf.Value, []byte("new value")) {
		t.Error(index1, "value mismatch\n")
	}

	if !bytes.Equal(ap.Leaf.Value, val2) {
		t.Errorf("Value mismatch %v / %v", ap.Leaf.Value, val2)
	}

	val3 := []byte("new value 2")
	if err := m.Set(index1, key1, val3); err != nil {
		t.Fatal(err)
	}

	ap = m.Get(index1)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(ap.Leaf.Value, val3) {
		t.Errorf("Value mismatch %v / %v", ap.Leaf.Value, val3)
	}
}

func TestTreeClone(t *testing.T) {
	key1 := "key1"
	index1 := crypto.StaticVRF(t).Compute([]byte(key1))
	val1 := []byte("value1")
	key2 := "key2"
	index2 := crypto.StaticVRF(t).Compute([]byte(key2))
	val2 := []byte("value2")

	m1, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	m1.recomputeHash()

	// clone new tree and insert new value
	m2 := m1.Clone()

	if err := m2.Set(index2, key2, val2); err != nil {
		t.Fatal(err)
	}
	m2.recomputeHash()

	// tree hash
	// right branch hash value is still the same
	/*if bytes.Equal(m1.root.leftHash, m2.root.leftHash) {
		t.Fatal("Bad clone")
	}
	if reflect.ValueOf(m1.root.leftHash).Pointer() == reflect.ValueOf(m2.root.leftHash).Pointer() ||
		reflect.ValueOf(m1.root.rightHash).Pointer() == reflect.ValueOf(m2.root.rightHash).Pointer() {
		t.Fatal("Bad clone")
	}*/

	// lookup
	ap := m2.Get(index1)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(ap.Leaf.Value, []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	ap = m2.Get(index2)
	if ap.Leaf.Value == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(ap.Leaf.Value, []byte("value2")) {
		t.Error(key2, "value mismatch\n")
	}
}
