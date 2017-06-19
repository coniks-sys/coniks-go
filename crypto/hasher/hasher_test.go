package hasher

import (
	"testing"
)

var fakeHasherID = "fakeHasher"

func fakeHasher() PADHasher {
	return nil
}

func TestHasherIsRegistered(t *testing.T) {
	RegisterHasher(fakeHasherID, fakeHasher)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Expected RegisterHasher to panic.")
		}
	}()
	RegisterHasher(fakeHasherID, fakeHasher)
}

func TestGetHasher(t *testing.T) {
	if _, ok := hashers[fakeHasherID]; !ok {
		RegisterHasher(fakeHasherID, fakeHasher)
	}

	_, err := Hasher(fakeHasherID)
	if err != nil {
		t.Error("Expect a hasher.")
	}
}
