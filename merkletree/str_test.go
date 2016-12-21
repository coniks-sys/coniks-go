package merkletree

import (
	"bytes"
	"reflect"
	"testing"
)

func TestVerifyHashChain(t *testing.T) {
	var N uint64 = 100

	keyPrefix := "key"
	valuePrefix := []byte("value")
	pad, err := NewPAD(&MockAd{""}, signKey, vrfPrivKey1, 10)
	if err != nil {
		t.Fatal(err)
	}

	savedSTR := pad.LatestSTR()

	pk, ok := pad.signKey.Public()
	if !ok {
		t.Fatal("Couldn't retrieve public-key.")
	}

	for i := uint64(1); i < N; i++ {
		key := keyPrefix + string(i)
		value := append(valuePrefix, byte(i))
		if err := pad.Set(key, value); err != nil {
			t.Fatal(err)
		}
		pad.Update(nil)

		// verify STR signature
		str := pad.LatestSTR()
		if !pk.Verify(str.Serialize(), str.Signature) {
			t.Fatal("Invalid STR signature at epoch", i)
		}

		// verify hash chain
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Spurious STR at epoch", i)
		}
		savedSTR = str
	}
}

func TestSTREncodingDecoding(t *testing.T) {
	pad, err := NewPAD(&MockAd{"data"}, signKey, vrfPrivKey1, 10)
	if err != nil {
		t.Fatal(err)
	}

	var buff bytes.Buffer
	if err = EncodeSTR(&buff, pad.LatestSTR()); err != nil {
		t.Fatal(err)
	}

	strGot, err := DecodeSTR(&buff)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(strGot.Ad, pad.LatestSTR().Ad) ||
		!bytes.Equal(strGot.tree.hash, pad.LatestSTR().tree.hash) ||
		!bytes.Equal(strGot.Signature, pad.LatestSTR().Signature) {
		t.Fatal("Malformed encoding/decoding")
	}
}
