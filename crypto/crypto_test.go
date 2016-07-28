package crypto

import (
	"testing"

	"golang.org/x/crypto/ed25519"
)

func verify(key SigningKey, message, sig []byte) bool {
	pk, ok := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(pk, message, sig)
}

// copied from official crypto.ed25519 tests
func TestSignVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig := Sign(key, message)
	if !verify(key, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if verify(key, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}
