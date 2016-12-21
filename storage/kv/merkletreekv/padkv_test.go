package merkletreekv

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func TestPADStoreLoad(t *testing.T) {
	utils.WithDB(func(db kv.DB) {
		key1 := "key"
		val1 := []byte("value")

		key2 := "key2"
		val2 := []byte("value2")

		key3 := "key3"
		val3 := []byte("value3")
		vrfPrivKey1, _ := vrf.GenerateKey(nil)
		signKey, _ := sign.GenerateKey(nil)

		pad, err := merkletree.NewPAD(&merkletree.MockAd{""}, signKey, vrfPrivKey1, 10)
		if err != nil {
			t.Fatal(err)
		}
		if err := pad.Set(key1, val1); err != nil {
			t.Fatal(err)
		}
		if err := pad.Set(key2, val2); err != nil {
			t.Fatal(err)
		}
		if err := pad.Set(key3, val3); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil)

		if err := StorePAD(db, pad); err != nil {
			t.Fatal(err)
		}

		padGot, err := LoadPAD(db, 10)
		if err != nil {
			t.Fatal(err)
		}
		ap, err := padGot.Lookup(key1)
		if ap.Leaf.Value == nil {
			t.Fatalf("Cannot find key: %v", key1)
		}
		padGot.Update(nil) // just to make sure everything is okay
	})
}
