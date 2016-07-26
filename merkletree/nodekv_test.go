package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func TestNodeSerializationAndDeserialization(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		m, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}

		key1 := "key1"
		val1 := []byte("value1")
		key2 := "key3"
		val2 := []byte("value2")
		index1 := vrf.Compute([]byte(key1), vrfPrivKey1)
		if err := m.Set(index1, key1, val1); err != nil {
			t.Fatal(err)
		}

		index2 := vrf.Compute([]byte(key2), vrfPrivKey1)
		if err := m.Set(index2, key2, val2); err != nil {
			t.Fatal(err)
		}

		m.recomputeHash()

		ap := m.Get(index1)
		if ap.Leaf().IsEmpty() {
			t.Fatal("Cannot find key:", key1)
		}

		enWant, ok := m.root.leftChild.(*emptyNode)
		if !ok {
			t.Fatal("Bad type insertion")
		}
		inWant, ok := m.root.rightChild.(*interiorNode)
		if !ok {
			t.Fatal("Bad type insertion")
		}
		lnWant := ap.Leaf().(*userLeafNode)

		wb := db.NewBatch()
		enWant.storeToKV(1, []bool{false}, wb)
		inWant.storeToKV(1, []bool{true}, wb)
		lnWant.storeToKV(1, util.ToBits(lnWant.index)[:lnWant.level], wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}

		// test empty node
		n, err := loadNode(db, 1, []bool{false})
		if err != nil {
			t.Fatal(err)
		}
		enGot, ok := n.(*emptyNode)
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
		n, err = loadNode(db, 1, []bool{true})
		if err != nil {
			t.Fatal(err)
		}
		inGot, ok := n.(*interiorNode)
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
		n, err = loadNode(db, 1, util.ToBits(lnWant.index)[:lnWant.level])
		if err != nil {
			t.Fatal(err)
		}
		lnGot, ok := n.(*userLeafNode)
		if !ok {
			t.Fatal("Bad type assertion")
		}
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
	})
}
