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
		var epoch uint64 = 1

		p := NewPolicies(2, vrfPrivKey1)
		m, err := NewMerkleTree()
		if err != nil {
			t.Fatal(err)
		}
		m.recomputeHash()
		str1 := NewSTR(signKey, p, m, epoch, make([]byte, crypto.HashSizeByte))
		wb := db.NewBatch()
		str1.StoreToKV(wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}

		strGot := new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, signKey, epoch)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(str1.Signature, strGot.Signature) ||
			!bytes.Equal(str1.PreviousSTRHash, strGot.PreviousSTRHash) ||
			str1.PreviousEpoch != strGot.PreviousEpoch ||
			str1.Epoch != strGot.Epoch {
			t.Fatal("Bad de/serialization",
				"expect", str1,
				"got", strGot)
		}

		str2 := NewSTR(signKey, p, m, epoch+1, crypto.Digest(str1.Signature))
		wb = db.NewBatch()
		str2.StoreToKV(wb)
		err = db.Write(wb)
		if err != nil {
			t.Fatal(err)
		}
		strGot = new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, signKey, epoch+1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(str2.Signature, strGot.Signature) ||
			!bytes.Equal(str2.PreviousSTRHash, strGot.PreviousSTRHash) ||
			str2.PreviousEpoch != strGot.PreviousEpoch ||
			str2.Epoch != strGot.Epoch {
			t.Fatal("Bad de/serialization",
				"expect", str2,
				"got", strGot)
		}

		// test get non-exist str from db
		strGot = new(SignedTreeRoot)
		err = strGot.LoadFromKV(db, signKey, epoch+2)
		if err != db.ErrNotFound() {
			t.Fatal("Got unexpected str from db")
		}
	})
}
