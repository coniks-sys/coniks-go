package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func TestSTRStore(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		p := NewPolicies(2, vrfPrivKey1)
		m, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		m.recomputeHash()
		str1 := NewSTR(signKey, p, m, 1, make([]byte, crypto.HashSizeByte))
		wb := db.NewBatch()
		str1.StoreToKV(wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}

		policies := new(ConiksPolicies)

		strGot := new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, policies, signKey, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(str1.tree.hash, strGot.tree.hash) ||
			!bytes.Equal(str1.PreviousSTRHash, strGot.PreviousSTRHash) ||
			str1.PreviousEpoch != strGot.PreviousEpoch ||
			str1.Epoch != strGot.Epoch {
			t.Fatal("Bad de/serialization",
				"expect", str1,
				"got", strGot)
		}

		str2 := NewSTR(signKey, p, m, 2, crypto.Digest(str1.Signature))
		wb = db.NewBatch()
		str2.StoreToKV(wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}
		strGot = new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, policies, signKey, 2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(str2.tree.hash, strGot.tree.hash) ||
			!bytes.Equal(str2.PreviousSTRHash, strGot.PreviousSTRHash) ||
			str2.PreviousEpoch != strGot.PreviousEpoch ||
			str2.Epoch != strGot.Epoch {
			t.Fatal("Bad de/serialization",
				"expect", str2,
				"got", strGot)
		}

		// test get non-exist str from db
		strGot = new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, policies, signKey, 3)
		if err != db.ErrNotFound() {
			t.Fatal("Got unexpected str from db")
		}
	})
}
