package crypto

import (
	"crypto/rand"
	"errors"
	"testing"
)

type testErrorRandReader struct{}

func (er testErrorRandReader) Read([]byte) (int, error) {
	return 0, errors.New("not enough entropy")
}

func TestMakeRand(t *testing.T) {
	r, err := MakeRand()
	if err != nil {
		t.Fatal(err)
	}
	// check if hashed the random output:
	if len(r) != DefaultHashSizeByte {
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
