package merkletree

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/coniks-sys/coniks-go/utils"
	"golang.org/x/crypto/sha3"
)

func TestOneEntry(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	var commit [32]byte
	var expect [32]byte

	key := "key"
	val := []byte("value")

	if err := m.Set(key, val); err != nil {
		t.Fatal(err)
	}
	m.recomputeHash()

	index := computePrivateIndex(key)

	// Check empty node hash
	h := sha3.NewShake128()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(m.nonce)
	h.Write(util.ToBytes([]bool{true}))
	h.Write(util.IntToBytes(1))
	h.Read(expect[:])
	if !bytes.Equal(m.root.rightHash, expect[:]) {
		t.Error("Wrong righ hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	r := m.Get(key)
	if r.Leaf().Value() == nil {
		t.Error("Cannot find value of key:", key)
		return
	}
	v := r.Leaf().Value()
	if !bytes.Equal(v, val) {
		t.Errorf("Value mismatch %v / %v", v, val)
	}

	// Check leaf node hash
	h.Reset()
	h.Write(r.Leaf().(*userLeafNode).salt)
	h.Write([]byte(key))
	h.Write(val)
	h.Read(commit[:])

	h.Reset()
	h.Write([]byte{LeafIdentifier})
	h.Write(m.nonce)
	h.Write(index)
	h.Write(util.IntToBytes(1))
	h.Write(commit[:])
	h.Read(expect[:])

	if !bytes.Equal(m.root.leftHash, expect[:]) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	r = m.Get("abc")
	if r.Leaf().Value() != nil {
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
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	if err := m.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key2, val2); err != nil {
		t.Fatal(err)
	}

	ap1 := m.Get(key1)
	if ap1.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	ap2 := m.Get(key2)
	if ap2.Leaf().Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}

	if !bytes.Equal(ap1.Leaf().Value(), []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(ap2.Leaf().Value(), []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
}

func TestThreeEntries(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")
	key3 := "key3"
	val3 := []byte("value3")

	if err := m.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key3, val3); err != nil {
		t.Fatal(err)
	}

	ap1 := m.Get(key1)
	if ap1.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	ap2 := m.Get(key2)
	if ap2.Leaf().Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	ap3 := m.Get(key3)
	if ap3.Leaf().Value() == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// since the first bit of ap2 index is false and the one of ap1 & ap3 are true
	if ap2.Leaf().Level() != 1 {
		t.Error("Malformed tree insertion")
	}

	// since n1 and n3 share first 2 bits
	if ap1.Leaf().Level() != 3 {
		t.Error("Malformed tree insertion")
	}
	if ap3.Leaf().Level() != 3 {
		t.Error("Malformed tree insertion")
	}

	if !bytes.Equal(ap1.Leaf().Value(), []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(ap2.Leaf().Value(), []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
	if !bytes.Equal(ap3.Leaf().Value(), []byte("value3")) {
		t.Error(key3, "value mismatch")
	}
}

func TestInsertExistedKey(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key"
	val1 := append([]byte(nil), "value"...)

	if err := m.Set(key1, val1); err != nil {
		t.Fatal(err)
	}

	val2 := []byte("new value")
	if err := m.Set(key1, val2); err != nil {
		t.Fatal(err)
	}

	ap := m.Get(key1)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(ap.Leaf().Value(), []byte("new value")) {
		t.Error(key1, "value mismatch\n")
	}

	if !bytes.Equal(ap.Leaf().Value(), val2) {
		t.Errorf("Value mismatch %v / %v", ap.Leaf().Value(), val2)
	}

	val3 := []byte("new value 2")
	if err := m.Set(key1, val3); err != nil {
		t.Fatal(err)
	}

	ap = m.Get(key1)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(ap.Leaf().Value(), val3) {
		t.Errorf("Value mismatch %v / %v", ap.Leaf().Value(), val3)
	}
}

func TestTreeClone(t *testing.T) {
	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m1, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	m1.recomputeHash()

	// clone new tree and insert new value
	m2 := m1.Clone()

	if err := m2.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	m2.recomputeHash()

	// tree hash
	// right branch hash value is still the same
	if bytes.Equal(m1.root.leftHash, m2.root.leftHash) {
		t.Fatal("Bad clone")
	}
	if reflect.ValueOf(m1.root.leftHash).Pointer() == reflect.ValueOf(m2.root.leftHash).Pointer() ||
		reflect.ValueOf(m1.root.rightHash).Pointer() == reflect.ValueOf(m2.root.rightHash).Pointer() {
		t.Fatal("Bad clone")
	}

	// lookup
	ap := m2.Get(key1)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(ap.Leaf().Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	ap = m2.Get(key2)
	if ap.Leaf().Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(ap.Leaf().Value(), []byte("value2")) {
		t.Error(key2, "value mismatch\n")
	}
}
