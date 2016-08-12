package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

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

func TestCommit(t *testing.T) {
	stuff := []byte("123")
	commit, err := NewCommit(stuff)
	if err != nil {
		t.Fatal(err)
	}
	if !commit.Verify(stuff) {
		t.Fatal("Commit doesn't verify!")
	}
}
