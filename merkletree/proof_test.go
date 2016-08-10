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
	if ap1.Leaf.Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	ap2 := m.Get(index2)
	if ap2.Leaf.Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	ap3 := m.Get(index3)
	if ap3.Leaf.Value() == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// proof of inclusion
	proof := m.Get(index3)
	// step 1. verify VRF index
	if !bytes.Equal(vrfPrivKey1.Compute([]byte(key3)), proof.LookupIndex) {
		t.Error("VRF verification returns false")
	}
	// step 2. verify commitment
	if !VerifyCommitment(proof.Leaf.Salt(), key3, proof.Leaf.Value(), proof.Leaf.Commitment()) {
		t.Fatal("Commitment verification returns false")
	}
	// step 3. verify auth path
	if !VerifyAuthPath(proof,
		proof.Leaf.Index(), proof.Leaf.Commitment(), proof.Leaf.Level(), proof.Leaf.IsEmpty(),
		m.hash) {
		t.Error("Proof of inclusion verification failed.")
	}
	if _, ok := proof.Leaf.(*userLeafNode); !ok {
		t.Error("Invalid proof of inclusion. Expect a userLeafNode in returned path")
	}

	// proof of absence
	absentIndex := vrfPrivKey1.Compute([]byte("123"))
	proof = m.Get(absentIndex) // shares the same prefix with an empty node
	if !bytes.Equal(vrfPrivKey1.Compute([]byte("123")), proof.LookupIndex) {
		t.Error("VRF verification returns false")
	}
	if !VerifyAuthPath(proof,
		proof.Leaf.Index(), proof.Leaf.Commitment(), proof.Leaf.Level(), proof.Leaf.IsEmpty(),
		m.hash) {
		t.Error("Proof of absence verification failed.")
	}
	if _, ok := proof.Leaf.(*emptyNode); !ok {
		t.Error("Invalid proof of absence. Expect an empty node in returned path")
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
	// assert these indices share the same prefix in the first bit
	if !bytes.Equal(util.ToBytes(util.ToBits(index1)[:proof.Leaf.Level()]),
		util.ToBytes(util.ToBits(absentIndex)[:proof.Leaf.Level()])) {
		t.Fatal("Expect these indices share the same prefix in the first bit")
	}
	if !bytes.Equal(vrfPrivKey1.Compute([]byte("a")), proof.LookupIndex) {
		t.Error("VRF verification returns false")
	}
	if !VerifyAuthPath(proof,
		proof.Leaf.Index(), proof.Leaf.Commitment(), proof.Leaf.Level(), proof.Leaf.IsEmpty(),
		m.hash) {
		t.Error("Proof of absence verification failed.")
	}
}

func TestEmptyNodeCommitment(t *testing.T) {
	n := node{parent: nil, level: 1}
	e := emptyNode{node: n, index: []byte("some index")}
	if c := e.Commitment(); c != nil {
		t.Fatal("Commitment of emptyNode should be nil")
	}
}
