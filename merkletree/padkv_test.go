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

		policies := new(ConiksPolicies)
		padGot, err := NewPADFromKV(db, policies, signKey, 10)
		if err != nil {
			t.Fatal(err)
		}
		ap, err := padGot.Lookup(key1)
		if ap.Leaf.Value() == nil {
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

//TODO: need to be fixed with GetSTR method.
func _TestGetOldSTR(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		key1 := "key"
		val1 := []byte("value")

		key2 := "key2"
		val2 := []byte("value2")

		key3 := "key3"
		val3 := []byte("value3")

		pad, err := NewPAD(NewPolicies(2, vrfPrivKey1), db, signKey, 2)
		if err != nil {
			t.Fatal(err)
		}
		if err := pad.Set(key1, val1); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil) // epoch = 1
		if err := pad.Set(key2, val2); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil) // epoch = 2
		if err := pad.Set(key3, val3); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil) // epoch = 3

		ap, err := pad.LookupInEpoch(key1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() != nil {
			t.Fatal("Unexpected key lookup at epoch", 0)
		}

		ap, err = pad.LookupInEpoch(key2, 1)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() != nil {
			t.Fatal("Unexpected key lookup at epoch", 1)
		}
		ap, err = pad.LookupInEpoch(key1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() == nil {
			t.Fatal("Cannot find key", key1, "at epoch", 1)
		}

		ap, err = pad.LookupInEpoch(key3, 2)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() != nil {
			t.Fatal("Unexpected key lookup at epoch", 2)
		}
		ap, err = pad.LookupInEpoch(key2, 2)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() == nil {
			t.Fatal("Cannot find key", key2, "at epoch", 2)
		}

		ap, err = pad.LookupInEpoch(key3, 3)
		if err != nil {
			t.Fatal(err)
		}
		if ap.Leaf.Value() == nil {
			t.Fatal("Cannot find key", key3, "at epoch", 3)
		}

	})
}

func BenchmarkStorePAD100K(b *testing.B) {
	// total number of entries in tree:
	NumEntries := uint64(100000)

	keyPrefix := "key"
	valuePrefix := []byte("value")
	snapLen := uint64(10)
	noUpdate := uint64(NumEntries + 1)
	pad, err := createPad(NumEntries, keyPrefix, valuePrefix, snapLen, noUpdate)
	if err != nil {
		b.Fatal(err)
	}
	util.WithDB(func(db kv.DB) {
		pad.db = db
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pad.Update(nil)
		}
	})
}

func BenchmarkLoadPAD100K(b *testing.B) {
	// total number of entries in tree:
	NumEntries := uint64(100000)

	keyPrefix := "key"
	valuePrefix := []byte("value")
	snapLen := uint64(10)
	noUpdate := uint64(NumEntries + 1)
	pad, err := createPad(NumEntries, keyPrefix, valuePrefix, snapLen, noUpdate)
	if err != nil {
		b.Fatal(err)
	}
	util.WithDB(func(db kv.DB) {
		pad.db = db
		pad.Update(nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p := new(ConiksPolicies)
			_, err := NewPADFromKV(db, p, signKey, snapLen)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
