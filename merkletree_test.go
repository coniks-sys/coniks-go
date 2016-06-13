package merkletree

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

var treeNonce = []byte("TREE NONCE")
var salt = []byte("salt")

var (
	pk, sk []byte
)

func init() {
	pk, sk, _ = ed25519.GenerateKey(rand.Reader)
}

func TestOneEntry(t *testing.T) {
	currentSTR = nil
	m := InitMerkleTree(treeNonce, salt, pk, sk)

	m.InitHistory(1, 1)
	var commit [32]byte
	var expect [32]byte

	key := "key"
	val := []byte("value")

	m.Set(key, val)
	m.RecomputeHash()

	index := computePrivateIndex(key)

	// Check leaf node hash
	h := sha3.NewShake256()
	h.Write(salt)
	h.Write([]byte(key))
	h.Write(val)
	h.Read(commit[:])

	h = sha3.NewShake256()
	h.Write([]byte{LeafIdentifier})
	h.Write(treeNonce)
	h.Write(index)
	h.Write(intToBytes(1))
	h.Write(commit[:])
	h.Read(expect[:])

	if !bytes.Equal(m.root.leftHash, expect[:]) {
		t.Error("Wrong left hash!",
			"expected", expect,
			"get", m.root.leftHash)
	}

	// Check empty node hash
	h = sha3.NewShake256()
	h.Write([]byte{EmptyBranchIdentifier})
	h.Write(treeNonce)
	h.Write(toBytes([]bool{true}))
	h.Write(intToBytes(1))
	h.Read(expect[:])
	if !bytes.Equal(m.root.rightHash, expect[:]) {
		t.Error("Wrong righ hash!",
			"expected", expect,
			"get", m.root.rightHash)
	}

	r, _, _ := LookUp(key)
	if r == nil {
		t.Error("Cannot find value of key:", key)
		return
	}
	v := r.Value()
	if !bytes.Equal(v, val) {
		t.Errorf("Value mismatch %v / %v", v, val)
	}

	r, _, _ = LookUp("abc")
	if r != nil {
		t.Error("Invalid look-up operation:", key)
		return
	}
}

func TestTwoEntries(t *testing.T) {
	currentSTR = nil
	m := InitMerkleTree(treeNonce, salt, pk, sk)
	m.InitHistory(1, 1)

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m.Set(key1, val1)
	m.RecomputeHash()
	m.Set(key2, val2)
	m.RecomputeHash()

	n1, _, _ := LookUp(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	n2, _, _ := LookUp(key2)
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
	m := InitMerkleTree(treeNonce, salt, pk, sk)
	m.InitHistory(1, 1)

	key1 := "key"
	val1 := append([]byte(nil), "value"...)

	m.Set(key1, val1)

	val2 := []byte("new value")
	if m.Set(key1, val2) != nil {
		t.Error("cannot insert new key-value to the tree")
	}

	val, _, _ := LookUp(key1)
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

	m1 := InitMerkleTree(treeNonce, salt, pk, sk)
	m1.InitHistory(1, 1)

	m1.Set(key1, val1)

	// clone new tree and insert new value
	m1 = m1.Clone()
	m1.UpdateHistory(2) // update history chain
	if err := m1.Set(key2, val2); err != nil {
		t.Error(err)
		return
	}

	// lookup
	r, _, _ := LookUp(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	r, _, _ = LookUp(key2)
	if r == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value2")) {
		t.Error(key2, "value mismatch\n")
	}
}

// scenario:
// 1st: epoch = 1
// 2nd: epoch = 3
// 3nd: epoch = 5 (latest STR)
func TestHistoryHashChain(t *testing.T) {
	currentSTR = nil
	var startupTime int64
	var epochInterval int64

	startupTime = 1
	epochInterval = 2

	key1 := "key"
	val1 := []byte("value")

	key2 := "key2"
	val2 := []byte("value2")

	key3 := "key3"
	val3 := []byte("value3")

	m1 := InitMerkleTree(treeNonce, salt, pk, sk)
	m1.InitHistory(startupTime, epochInterval)
	m1.Set(key1, val1)
	m1.RecomputeHash()

	m2 := m1.Clone()
	m2.Set(key2, val2)
	m2.RecomputeHash()
	m2.UpdateHistory(startupTime + epochInterval)

	m3 := m2.Clone()
	m3.Set(key3, val3)
	m3.RecomputeHash()
	m3.UpdateHistory(startupTime + 2*epochInterval)

	for i := 0; i < 2; i++ {
		str := GetSTR(startupTime + int64(i)*epochInterval)
		if str == nil {
			t.Error("Cannot get STR having epoch", startupTime+int64(i)*epochInterval)
			return
		}

		if str.epoch != startupTime+int64(i)*epochInterval {
			t.Error("Got invalid STR")
			return
		}
	}

	str := GetSTR(6)
	if str == nil {
		t.Error("Cannot get STR")
		return
	}

	if str.epoch != 5 {
		t.Error("Got invalid STR")
	}

	// check tree root of each STR is valid
	if reflect.ValueOf(m1.root).Pointer() != reflect.ValueOf(GetSTR(1).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m2.root).Pointer() != reflect.ValueOf(GetSTR(3).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m3.root).Pointer() != reflect.ValueOf(GetSTR(5).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}

	// lookup
	r, _, _ := LookUp(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	r, _, _ = LookUp(key2)
	if r == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(r.Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	r, _, _ = LookUp(key3)
	if r == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(r.Value(), val3) {
		t.Error(key3, "value mismatch")
	}

	r, _, _ = LookUpInEpoch(key2, 1)
	if r != nil {
		t.Error("Found unexpected key", key2, "in epoch", 1)
	}

	r, _, _ = LookUpInEpoch(key3, 4)
	if r != nil {
		t.Error("Found unexpected key", key3, "in epoch", 4)
	}

	r, _, _ = LookUpInEpoch(key3, 5)
	if r == nil {
		t.Error("Cannot find key", key3, "in epoch", 5)
	}
}
