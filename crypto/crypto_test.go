package crypto

import "testing"

// copied from official crypto.ed25519 tests
func TestSignVerify(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig := Sign(key, message)
	if !Verify(key, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(key, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}
