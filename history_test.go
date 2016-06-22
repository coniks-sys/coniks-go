package merkletree

import (
	"bytes"
	"reflect"
	"testing"
)

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
	history := NewHistory(m1, signKey, startupTime, epochInterval)
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
