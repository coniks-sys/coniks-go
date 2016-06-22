package merkletree

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
	"golang.org/x/crypto/sha3"
)

var treeNonce = []byte("TREE NONCE")
var salt = []byte("salt")

func TestOneEntry(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)

	var commit [32]byte
	var expect [32]byte

	key := "key"
	val := []byte("value")

	m.Set(key, val)
	m.RecomputeHash()

	index := computePrivateIndex(key)

	// Check leaf node hash
	h := sha3.NewShake128()
	h.Write(salt)
	h.Write([]byte(key))
	h.Write(val)
	h.Read(commit[:])

	h = sha3.NewShake128()
	h.Write([]byte{LeafIdentifier})
	h.Write(treeNonce)
	h.Write(index)
	h.Write(util.IntToBytes(1))
	h.Write(commit[:])
	h.Read(expect[:])

	if !bytes.Equal(m.root.leftHash, expect[:]) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	// Check empty node hash
	h = sha3.NewShake128()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(treeNonce)
	h.Write(util.ToBytes([]bool{true}))
	h.Write(util.IntToBytes(1))
	h.Read(expect[:])
	if !bytes.Equal(m.root.rightHash, expect[:]) {
		t.Error("Wrong righ hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	r, proof := m.Get(key)
	if r == nil {
		t.Error("Cannot find value of key:", key)
		return
	}
	v := r.Value()
	if !bytes.Equal(v, val) {
		t.Errorf("Value mismatch %v / %v", v, val)
	}

	if !bytes.Equal(m.root.hash(), proof[0].GetHash()) {
		t.Error("Invalid proof of inclusion")
	}

	if !bytes.Equal(m.root.leftHash, proof[1].GetHash()) {
		t.Error("Invalid proof of inclusion")
	}

	r, _ = m.Get("abc")
	if r != nil {
		t.Error("Invalid look-up operation:", key)
		return
	}
}

func TestTwoEntries(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m.Set(key1, val1)
	m.Set(key2, val2)
	m.RecomputeHash()

	n1, _ := m.Get(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	n2, _ := m.Get(key2)
	if n2 == nil {
		t.Error("Cannot find key:", key2)
		return
	}

	if !bytes.Equal(n1.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(n2.Value(), []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
}

func TestThreeEntries(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")
	key3 := "key3"
	val3 := []byte("value3")

	m.Set(key1, val1)
	m.Set(key2, val2)
	m.Set(key3, val3)
	m.RecomputeHash()

	n1, _ := m.Get(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	n2, _ := m.Get(key2)
	if n2 == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	n3, _ := m.Get(key3)
	if n3 == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// since the first bit of n2 index is false and the one of n1 & n3 are true
	if reflect.ValueOf(m.root.leftChild).Pointer() !=
		reflect.ValueOf(n2.(*userLeafNode)).Pointer() {
		t.Error("Malformed tree insertion")
	}
	if n2.(*userLeafNode).level != 1 {
		t.Error("Malformed tree insertion")
	}

	// since n1 and n3 share first 2 bits
	if n1.(*userLeafNode).level != 3 {
		t.Error("Malformed tree insertion")
	}
	if n3.(*userLeafNode).level != 3 {
		t.Error("Malformed tree insertion")
	}
	// n1 and n3 should have same parent
	if reflect.ValueOf(n1.(*userLeafNode).parent).Pointer() !=
		reflect.ValueOf(n3.(*userLeafNode).parent).Pointer() {
		t.Error("Malformed tree insertion")
	}
	if reflect.ValueOf(n1.(*userLeafNode).parent.(*interiorNode).leftChild).Pointer() !=
		reflect.ValueOf(n3).Pointer() {
		t.Error("Malformed tree insertion")
	}
	if reflect.ValueOf(n3.(*userLeafNode).parent.(*interiorNode).rightChild).Pointer() !=
		reflect.ValueOf(n1).Pointer() {
		t.Error("Malformed tree insertion")
	}

	if !bytes.Equal(n1.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch")
	}
	if !bytes.Equal(n2.Value(), []byte("value2")) {
		t.Error(key2, "value mismatch")
	}
	if !bytes.Equal(n3.Value(), []byte("value3")) {
		t.Error(key3, "value mismatch")
	}
}

func TestInsertExistedKey(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)

	key1 := "key"
	val1 := append([]byte(nil), "value"...)

	m.Set(key1, val1)

	val2 := []byte("new value")
	m.Set(key1, val2)

	val, _ := m.Get(key1)
	if val == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(val.Value(), []byte("new value")) {
		t.Error(key1, "value mismatch\n")
	}
}

func TestTreeClone(t *testing.T) {
	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m1 := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)
	m1.Set(key1, val1)

	// clone new tree and insert new value
	m2 := m1.Clone()

	m2.Set(key2, val2)

	// lookup
	r, _ := m2.Get(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	r, _ = m2.Get(key2)
	if r == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value2")) {
		t.Error(key2, "value mismatch\n")
	}
}
