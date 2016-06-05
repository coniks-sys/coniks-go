package merkletree

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

var treeNonce = []byte("TREE NONCE")
var salt = []byte("salt")
var hashSuite = HashSuite{Hash: sha256.New(), HashSizeByte: 32}

func TestOneEntry(t *testing.T) {
	m := InitMerkleTree(treeNonce, salt, hashSuite)
	pubKeyBytes := append([]byte(nil), "key"...)
	ops := Operation{
		Key:   "tester",
		Value: pubKeyBytes,
	}
	m.Set(ops)
	m.RecomputeHash()

	h := sha256.New()
	index := m.computePrivateIndex(ops.Key)
	stringBytes := append([]byte(nil), ops.Key...)
	h.Write(stringBytes)
	expect := h.Sum(nil)

	if !bytes.Equal(expect, index) {
		t.Error("Wrong username to index hash")
	}

	// Check leaf node hash
	h = sha256.New()
	h.Write(salt)
	h.Write(append([]byte(nil), ops.Key...))
	h.Write(append([]byte(nil), ops.Value...))
	commit := h.Sum(nil)

	h = sha256.New()
	h.Write([]byte{LeafIdentifier})
	h.Write(treeNonce)
	h.Write(index)
	h.Write(intToBytes(1))
	h.Write(commit)
	expect = h.Sum(nil)

	if !bytes.Equal(m.root.rightHash, expect) {
		t.Error("Wrong right hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	// Check empty node hash
	h = sha256.New()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(treeNonce)
	h.Write([]byte{0})
	h.Write(intToBytes(1))
	expect = h.Sum(nil)
	if !bytes.Equal(m.root.leftHash, expect) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	r := m.LookUp(ops.Key)
	if r == nil {
		t.Error("Cannot find username: ", ops.Key)
	}

	v := r.Value()
	if !bytes.Equal(v, pubKeyBytes) {
		t.Errorf("Public key mismatch %v / %v", v, pubKeyBytes)
	}
}

func TestTwoEntries(t *testing.T) {
	m := InitMerkleTree(treeNonce, salt, hashSuite)
	ops1 := Operation{
		Key:   "tester1",
		Value: append([]byte(nil), "key1"...),
	}

	ops2 := Operation{
		Key:   "tester2",
		Value: append([]byte(nil), "key2"...),
	}

	m.Set(ops1)
	m.Set(ops2)
	m.RecomputeHash()

	n1 := m.LookUp(ops1.Key)
	if n1 == nil {
		t.Error("Cannot find username: ", ops1.Key)
	}

	n2 := m.LookUp(ops2.Key)
	if n2 == nil {
		t.Error("Cannot find username: ", ops2.Key)
	}

	if !bytes.Equal(n1.Value(), append([]byte(nil), "key1"...)) {
		t.Error(ops1.Key, "public key mismatch")
	}
	if !bytes.Equal(n2.Value(), append([]byte(nil), "key2"...)) {
		t.Error(ops2.Key, "public key mismatch")
	}
}

func TestInsertExistedKey(t *testing.T) {
	m := InitMerkleTree(treeNonce, salt, hashSuite)
	ops := Operation{
		Key:   "tester",
		Value: append([]byte(nil), "key1"...),
	}
	if m.Set(ops) != nil {
		t.Error("cannot insert new binding to the tree")
	}

	ops = Operation{
		Key:   "tester",
		Value: append([]byte(nil), "key2"...),
	}
	if m.Set(ops) != nil {
		t.Error("cannot insert new binding to the tree")
	}

	val := m.LookUp(ops.Key)
	if val == nil {
		t.Error("Cannot find username: ", ops.Key)
	}

	if !bytes.Equal(val.Value(), append([]byte(nil), "key2"...)) {
		t.Error(ops.Key, "public key mismatch\n")
	}
}
