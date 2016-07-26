package merkletree

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/storage/kv/leveldbkv"
	"github.com/syndtr/goleveldb/leveldb"
)

// copyrighted by the Coname authors
func withDB(f func(kv.DB)) {
	dir, err := ioutil.TempDir("", "merkletree")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	f(leveldbkv.Wrap(db))
}

func TestTreeStore(t *testing.T) {
	withDB(func(db kv.DB) {
		key1 := "key1"
		val1 := []byte("value1")
		key2 := "key2"
		val2 := []byte("value2")

		m1, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		if err := m1.Set(key1, val1); err != nil {
			t.Fatal(err)
		}
		if err := m1.Set(key2, val2); err != nil {
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

		ap := m2.Get(key1)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key1)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val1) {
			t.Error(key1, "value mismatch")
		}

		ap = m2.Get(key2)
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
	withDB(func(db kv.DB) {
		key1 := "key1"
		val1 := []byte("value1")
		key2 := "key3"
		val2 := []byte("value2")

		m1, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		if err := m1.Set(key1, val1); err != nil {
			t.Fatal(err)
		}
		if err := m1.Set(key2, val2); err != nil {
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

		m2_1, err := ReconstructBranch(db, 1, computePrivateIndex(key1))
		if err != nil {
			t.Fatal(err)
		}
		ap := m2_1.Get(key1)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key1)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val1) {
			t.Error(key1, "value mismatch")
		}

		m2_2, err := ReconstructBranch(db, 1, computePrivateIndex(key2))
		if err != nil {
			t.Fatal(err)
		}
		ap = m2_2.Get(key2)
		if ap.Leaf().IsEmpty() {
			t.Error("Cannot find key:", key2)
			return
		}
		if !bytes.Equal(ap.Leaf().Value(), val2) {
			t.Error(key2, "value mismatch")
		}
	})
}
