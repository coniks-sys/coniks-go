package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func TestPadStore(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		key1 := "key"
		val1 := []byte("value")

		key2 := "key2"
		val2 := []byte("value2")

		key3 := "key3"
		val3 := []byte("value3")

		pad, err := NewPAD(NewPolicies(2, vrfPrivKey1), db, signKey, 10)
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

		padGot, err := NewPADFromKV(db, signKey, 10)
		if err != nil {
			t.Fatal(err)
		}
		ap, err := padGot.Lookup(key1)
		if ap.Leaf().IsEmpty() {
			t.Fatalf("Cannot find key: %v", key1)
		}
		if !bytes.Equal(pad.tree.hash, padGot.tree.hash) ||
			!bytes.Equal(pad.latestSTR.Serialize(), padGot.latestSTR.Serialize()) {
			t.Fatal("Malformed PAD construction from db",
				"want", pad.latestSTR.Serialize(),
				"got", padGot.latestSTR.Serialize())
		}
		padGot.Update(nil) // just to make sure everything is okay
	})
}
