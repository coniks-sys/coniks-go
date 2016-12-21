package merkletreekv

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func TestSTRStore(t *testing.T) {
	utils.WithDB(func(db kv.DB) {
		key1 := "key"
		val1 := []byte("value")

		key2 := "key2"
		val2 := []byte("value2")

		vrfPrivKey1, _ := vrf.GenerateKey(nil)
		signKey, _ := sign.GenerateKey(nil)

		pad, err := merkletree.NewPAD(&merkletree.MockAd{""}, signKey, vrfPrivKey1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if err := pad.Set(key1, val1); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil)
		str1 := pad.LatestSTR()
		if err := StoreSTR(db, str1); err != nil {
			t.Fatal(err)
		}

		if err := pad.Set(key2, val2); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil)
		str2 := pad.LatestSTR()
		if err := StoreSTR(db, str2); err != nil {
			t.Fatal(err)
		}

		// test loading STR from db
		strGot1, err := LoadSTR(db, 1)
		if err != nil {
			t.Fatal(err)
		}
		strGot2, err := LoadSTR(db, 2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(str1.Signature, strGot1.Signature) ||
			!bytes.Equal(str1.PreviousSTRHash, strGot1.PreviousSTRHash) ||
			str1.PreviousEpoch != strGot1.PreviousEpoch ||
			str1.Epoch != strGot1.Epoch {
			t.Fatal("Bad STR loading/storing",
				"expect", str1,
				"got", strGot1)
		}

		if !bytes.Equal(str2.Signature, strGot2.Signature) ||
			!bytes.Equal(str2.PreviousSTRHash, strGot2.PreviousSTRHash) ||
			str2.PreviousEpoch != strGot2.PreviousEpoch ||
			str2.Epoch != strGot2.Epoch {
			t.Fatal("Bad STR loading/storing",
				"expect", str2,
				"got", strGot2)
		}

		// test get non-exist str from db
		if _, err = LoadSTR(db, 3); err != db.ErrNotFound() {
			t.Fatal("Got unexpected STR from db")
		}

		// test key lookup from old STRs - see tests in kv/directorykv
	})
}
