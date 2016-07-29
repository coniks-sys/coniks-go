package sign

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// copied from official crypto.ed25519 tests
func TestVerifySignature(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig := key.Sign(message)

	pk, ok := key.Public()
	if !ok {
		t.Errorf("bad PK?")
	}

	if !pk.Verify(message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if pk.Verify(wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestDigest(t *testing.T) {
	msg := []byte("test message")
	d := Digest(msg)
	if len(d) != HashSizeByte {
		t.Fatal("Computation of Hash failed.")
	}
	if bytes.Equal(d, make([]byte, HashSizeByte)) {
		t.Fatal("Hash is all zeros.")
	}
}

type testErrorRandReader struct{}

func (er testErrorRandReader) Read([]byte) (int, error) {
	return 0, errors.New("Not enough entropy!")
}

func TestMakeRand(t *testing.T) {
	r, err := MakeRand()
	if err != nil {
		t.Fatal(err)
	}
	// check if hashed the random output:
	if len(r) != HashSizeByte {
		t.Fatal("Looks like Digest wasn't called correctly.")
	}
	orig := rand.Reader
	rand.Reader = testErrorRandReader{}
	r, err = MakeRand()
	if err == nil {
		t.Fatal("No error returned")
	}
	rand.Reader = orig
}
