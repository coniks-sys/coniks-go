package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
	"github.com/yahoo/coname/vrf"
)

func TestTreeStore(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		key1 := "key1"
		val1 := []byte("value1")
		key2 := "key2"
		val2 := []byte("value2")

		m1, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		index1 := vrf.Compute([]byte(key1), vrfPrivKey1)
		if err := m1.Set(index1, key1, val1); err != nil {
			t.Fatal(err)
		}
		index2 := vrf.Compute([]byte(key2), vrfPrivKey1)
		if err := m1.Set(index2, key2, val2); err != nil {
			t.Fatal(err)
		}
		m1.recomputeHash()

		wb := db.NewBatch()
		m1.StoreToKV(1, wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}

		m2, err := NewMerkleTreeFromKV(db, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m2.nonce, m1.nonce) ||
			!bytes.Equal(m2.root.Hash(m1), m1.hash) {
			t.Fatal("Bad tree construction")
		}

		ap := m2.Get(index1)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key1)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val1) {
			t.Error(key1, "value mismatch")
		}

		ap = m2.Get(index2)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key2)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val2) {
			t.Error(key2, "value mismatch")
		}
	})
}

func TestReconstructBranch(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		key1 := "key1"
		val1 := []byte("value1")
		key2 := "key3"
		val2 := []byte("value2")

		m1, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		index1 := vrf.Compute([]byte(key1), vrfPrivKey1)
		if err := m1.Set(index1, key1, val1); err != nil {
			t.Fatal(err)
		}
		index2 := vrf.Compute([]byte(key2), vrfPrivKey1)
		if err := m1.Set(index2, key2, val2); err != nil {
			t.Fatal(err)
		}
		m1.recomputeHash()

		wb := db.NewBatch()
		m1.StoreToKV(1, wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}

		if err != nil {
			t.Fatal(err)
		}

		m2_1, err := ReconstructBranch(db, 1, index1)
		if err != nil {
			t.Fatal(err)
		}
		ap := m2_1.Get(index1)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key1)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val1) {
			t.Error(key1, "value mismatch",
				"want", val1,
				"get", ap.Leaf().Value())
		}

		m2_2, err := ReconstructBranch(db, 1, index2)
		if err != nil {
			t.Fatal(err)
		}
		ap = m2_2.Get(index2)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key2)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val2) {
			t.Error(key2, "value mismatch")
		}
	})
}
