package merkletree

import (
	"bytes"
	"testing"
)

func TestNodeSerializationAndDeserialization(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key3"
	val2 := []byte("value2")

	if err := m.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key2, val2); err != nil {
		t.Fatal(err)
	}

	m.recomputeHash()

	ap := m.Get(key1)
	if ap.Leaf().IsEmpty() {
		t.Fatal("Cannot find key:", key1)
	}

	ap = m.Get(key2)
	if ap.Leaf().IsEmpty() {
		t.Fatal("Cannot find key:", key2)
	}

	// test empty node
	enWant, ok := m.root.leftChild.(*emptyNode)
	if !ok {
		t.Fatal("Bad type insertion")
	}
	enGot, ok := deserializeNode(m.root.leftChild.serialize()).(*emptyNode)
	if !ok {
		t.Fatal("Bad type assertion")
	}
	if enGot.level != enWant.level ||
		!bytes.Equal(enGot.index, enWant.index) {
		t.Fatal("Bad de/serialization",
			"expect", enWant.level,
			"got", enGot.level,
			"expect", enWant.index,
			"got", enGot.index)
	}

	// test interior node
	inWant, ok := m.root.rightChild.(*interiorNode)
	if !ok {
		t.Fatal("Bad type insertion")
	}
	inGot, ok := deserializeNode(m.root.rightChild.serialize()).(*interiorNode)
	if !ok {
		t.Fatal("Bad type assertion")
	}
	if inGot.level != inWant.level ||
		!bytes.Equal(inGot.leftHash, inWant.leftHash) ||
		!bytes.Equal(inGot.rightHash, inWant.rightHash) {
		t.Fatal("Bad de/serialization",
			"expect", inWant,
			"got", inGot)
	}

	// test leaf node
	lnWant := ap.Leaf().(*userLeafNode)
	lnGot := deserializeNode(ap.Leaf().(*userLeafNode).serialize()).(*userLeafNode)
	if lnGot.level != lnWant.level ||
		!bytes.Equal(lnGot.index, lnWant.index) ||
		lnGot.key != lnWant.key ||
		!bytes.Equal(lnGot.value, lnWant.value) ||
		!bytes.Equal(lnGot.salt, lnWant.salt) ||
		!bytes.Equal(lnGot.commitment, lnWant.commitment) {
		t.Fatal("Bad de/serialization",
			"expect", inWant,
			"got", inGot)
	}
}
