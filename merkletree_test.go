package merkletree

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

var treeNonce = []byte("TREE NONCE")
var salt = []byte("salt")
var hashFunc = HashFunction{Hash: sha256.New(), HashSizeByte: 32, HashId: crypto.SHA256}

func TestOneEntry(t *testing.T) {
	m := InitMerkleTree(treeNonce, salt, hashFunc, scheme)
	m.InitHistory(nil, 1, 1)

	key := "key"
	val := []byte("value")

	m.Set(key, val)
	m.RecomputeHash()

	index := m.computePrivateIndex(key)

	// Check leaf node hash
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(key))
	h.Write(val)
	commit := h.Sum(nil)

	h = sha256.New()
	h.Write([]byte{LeafIdentifier})
	h.Write(treeNonce)
	h.Write(index)
	h.Write(intToBytes(1))
	h.Write(commit)
	expect := h.Sum(nil)

	if !bytes.Equal(m.root.leftHash, expect) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	// Check empty node hash
	h = sha256.New()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(treeNonce)
	h.Write(toBytes([]bool{true}))
	h.Write(intToBytes(1))
	expect = h.Sum(nil)
	if !bytes.Equal(m.root.rightHash, expect) {
		t.Error("Wrong righ hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	r := m.LookUp(key)
	if r == nil {
		t.Error("Cannot find value of key:", key)
		return
	}

	v := r.Value()
	if !bytes.Equal(v, val) {
		t.Errorf("Value mismatch %v / %v", v, val)
	}
}

func TestTwoEntries(t *testing.T) {
	currentSTR = nil
	m := InitMerkleTree(treeNonce, salt, hashFunc, scheme)
	m.InitHistory(nil, 1, 1)

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m.Set(key1, val1)
	m.RecomputeHash()
	m.Set(key2, val2)
	m.RecomputeHash()

	n1 := m.LookUp(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	n2 := m.LookUp(key2)
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

func TestInsertExistedKey(t *testing.T) {
	currentSTR = nil
	m := InitMerkleTree(treeNonce, salt, hashFunc, scheme)
	m.InitHistory(nil, 1, 1)

	key1 := "key"
	val1 := append([]byte(nil), "value"...)

	m.Set(key1, val1)

	val2 := []byte("new value")
	if m.Set(key1, val2) != nil {
		t.Error("cannot insert new key-value to the tree")
	}

	val := m.LookUp(key1)
	if val == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	if !bytes.Equal(val.Value(), []byte("new value")) {
		t.Error(key1, "value mismatch\n")
	}
}

func TestTreeClone(t *testing.T) {
	currentSTR = nil
	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m1 := InitMerkleTree(treeNonce, salt, hashFunc, scheme)
	m1.InitHistory(nil, 1, 1)

	m1.Set(key1, val1)

	// clone new tree and insert new value
	m2 := m1.clone()
	m2.UpdateHistory(nil, 2) // update history chain
	if err := m2.Set(key2, val2); err != nil {
		t.Error(err)
		return
	}

	// lookup
	r := m1.LookUp(key1)
	if r == nil {
		t.Error("Cannot find key in tree 1:", key1)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	r = m1.LookUp(key2)
	if r != nil {
		t.Error("Invalid tree")
	}

	r = m2.LookUp(key1)
	if r == nil {
		t.Error("Cannot find key in tree 2:", key1)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	r = m2.LookUp(key2)
	if r == nil {
		t.Error("Cannot find key in tree 2:", key2)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value2")) {
		t.Error(key2, "value mismatch\n")
	}
}
