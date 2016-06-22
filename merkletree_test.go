package merkletree

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"

	"golang.org/x/crypto/sha3"
)

var treeNonce = []byte("TREE NONCE")
var salt = []byte("salt")

var (
	key crypto.KeyPair
)

func init() {
	key = crypto.GenerateKey()
}

func TestOneEntry(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)

	history := NewHistory(m, key, 1, 1)
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

	r, proof := history.Get(key)
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

	r, _ = history.Get("abc")
	if r != nil {
		t.Error("Invalid look-up operation:", key)
		return
	}
}

func TestTwoEntries(t *testing.T) {
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)
	history := NewHistory(m, key, 1, 1)

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")

	m.Set(key1, val1)
	m.RecomputeHash()
	m.Set(key2, val2)
	m.RecomputeHash()

	n1, _ := history.Get(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}

	n2, _ := history.Get(key2)
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
	m := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)
	history := NewHistory(m, key, 1, 1)

	key1 := "key"
	val1 := append([]byte(nil), "value"...)

	m.Set(key1, val1)

	val2 := []byte("new value")
	m.Set(key1, val2)

	val, _ := history.Get(key1)
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
	history := NewHistory(m1, key, 1, 1)

	m1.Set(key1, val1)

	// clone new tree and insert new value
	m1 = m1.Clone()
	history.UpdateHistory(m1, 2) // update history chain
	m1.Set(key2, val2)

	// lookup
	r, _ := history.Get(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), []byte("value1")) {
		t.Error(key1, "value mismatch\n")
	}

	r, _ = history.Get(key2)
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

	m1 := InitMerkleTree(&DefaultPolicies{}, treeNonce, salt)
	history := NewHistory(m1, key, startupTime, epochInterval)
	m1.Set(key1, val1)
	m1.RecomputeHash()

	m2 := m1.Clone()
	m2.Set(key2, val2)
	m2.RecomputeHash()
	history.UpdateHistory(m2, startupTime+epochInterval)

	m3 := m2.Clone()
	m3.Set(key3, val3)
	m3.RecomputeHash()
	history.UpdateHistory(m3, startupTime+2*epochInterval)

	for i := 0; i < 2; i++ {
		str := history.GetSTR(startupTime + int64(i)*epochInterval)
		if str == nil {
			t.Error("Cannot get STR having epoch", startupTime+int64(i)*epochInterval)
			return
		}

		if str.epoch != startupTime+int64(i)*epochInterval {
			t.Error("Got invalid STR")
			return
		}
	}

	str := history.GetSTR(6)
	if str == nil {
		t.Error("Cannot get STR")
		return
	}

	if str.epoch != 5 {
		t.Error("Got invalid STR")
	}

	// check tree root of each STR is valid
	if reflect.ValueOf(m1.root).Pointer() !=
		reflect.ValueOf(history.GetSTR(1).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m2.root).Pointer() !=
		reflect.ValueOf(history.GetSTR(3).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m3.root).Pointer() !=
		reflect.ValueOf(history.GetSTR(5).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}

	// lookup
	r, _ := history.Get(key1)
	if r == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	if !bytes.Equal(r.Value(), val1) {
		t.Error(key1, "value mismatch")
	}

	r, _ = history.Get(key2)
	if r == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	if !bytes.Equal(r.Value(), val2) {
		t.Error(key2, "value mismatch")
	}

	r, _ = history.Get(key3)
	if r == nil {
		t.Error("Cannot find key:", key3)
		return
	}
	if !bytes.Equal(r.Value(), val3) {
		t.Error(key3, "value mismatch")
	}

	r, _ = history.GetInEpoch(key2, 1)
	if r != nil {
		t.Error("Found unexpected key", key2, "in epoch", 1)
	}

	r, _ = history.GetInEpoch(key3, 4)
	if r != nil {
		t.Error("Found unexpected key", key3, "in epoch", 4)
	}

	r, _ = history.GetInEpoch(key3, 5)
	if r == nil {
		t.Error("Cannot find key", key3, "in epoch", 5)
	}
}
