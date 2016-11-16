package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/utils"
)

func TestVerifyProof(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := vrfPrivKey1.Compute([]byte(key1))
	val1 := []byte("value1")
	key2 := "key2"
	index2 := vrfPrivKey1.Compute([]byte(key2))
	val2 := []byte("value2")
	key3 := "key3"
	index3 := vrfPrivKey1.Compute([]byte(key3))
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

	m.recomputeHash()

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
	ap3 := m.Get(index3)
	if ap3.Leaf.Value == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// proof of inclusion
	proof := m.Get(index3)
	if proof.Leaf.Value == nil {
		t.Fatal("Expect returned leaf's value is not nil")
	}
	// ensure this is a proof of inclusion by comparing the returned indices
	// and verifying the VRF index as well.
	if !bytes.Equal(proof.LookupIndex, proof.Leaf.Index) ||
		!bytes.Equal(vrfPrivKey1.Compute([]byte(key3)), proof.LookupIndex) {
		t.Fatal("Expect a proof of inclusion")
	}
	// verify auth path
	if !proof.Verify([]byte(key3), val3, m.hash) {
		t.Error("Proof of inclusion verification failed.")
	}

	// proof of absence
	absentIndex := vrfPrivKey1.Compute([]byte("123"))
	proof = m.Get(absentIndex) // shares the same prefix with an empty node
	if proof.Leaf.Value != nil {
		t.Fatal("Expect returned leaf's value is nil")
	}
	// ensure this is a proof of absence
	if bytes.Equal(proof.LookupIndex, proof.Leaf.Index) ||
		!bytes.Equal(vrfPrivKey1.Compute([]byte("123")), proof.LookupIndex) {
		t.Fatal("Expect a proof of absence")
	}
	if !proof.Verify([]byte("123"), nil, m.hash) {
		t.Error("Proof of absence verification failed.")
	}
}

func TestVerifyProofSamePrefix(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := vrfPrivKey1.Compute([]byte(key1))
	val1 := []byte("value1")
	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	m.recomputeHash()
	absentIndex := vrfPrivKey1.Compute([]byte("a"))
	proof := m.Get(absentIndex) // shares the same prefix with leaf node key1
	if proof.Leaf.Value != nil {
		t.Fatal("Expect returned leaf's value is nil")
	}
	// ensure this is a proof of absence
	if bytes.Equal(proof.LookupIndex, proof.Leaf.Index) ||
		!bytes.Equal(vrfPrivKey1.Compute([]byte("a")), proof.LookupIndex) {
		t.Fatal("Expect a proof of absence")
	}
	// assert these indices share the same prefix in the first bit
	if !bytes.Equal(utils.ToBytes(utils.ToBits(index1)[:proof.Leaf.Level]),
		utils.ToBytes(utils.ToBits(absentIndex)[:proof.Leaf.Level])) {
		t.Fatal("Expect these indices share the same prefix in the first bit")
	}
	if !proof.Verify([]byte("a"), nil, m.hash) {
		t.Error("Proof of absence verification failed.")
	}

	// re-get proof of inclusion
	// for testing the commitment assignment
	proof = m.Get(index1)
	if proof.Leaf.Value == nil {
		t.Fatal("Expect returned leaf's value is not nil")
	}
	// ensure this is a proof of inclusion by comparing the returned indices
	// and verifying the VRF index as well.
	if !bytes.Equal(proof.LookupIndex, proof.Leaf.Index) ||
		!bytes.Equal(vrfPrivKey1.Compute([]byte(key1)), proof.LookupIndex) {
		t.Fatal("Expect a proof of inclusion")
	}
	// step 2. verify auth path
	if !proof.Verify([]byte(key1), val1, m.hash) {
		t.Error("Proof of inclusion verification failed.")
	}
}
