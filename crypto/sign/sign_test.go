package sign

import (
	"bytes"
	"testing"
)

// copied from official crypto.ed25519 tests
func TestVerifySignature(t *testing.T) {
	key, err := GenerateKey(nil)
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

func TestConvertPrivateKeyToPublicKey(t *testing.T) {
	sk, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	pk, ok := sk.Public()
	if !ok {
		t.Fatal("Couldn't obtain public key.")
	}
	if !bytes.Equal(pk, sk[32:]) {
		t.Fatal("Raw byte respresentation doesn't match public key.")
	}
}
