package merkletree

import (
	"crypto/rand"
	"testing"

	"reflect"

	"golang.org/x/crypto/ed25519"
)

type Ed25519Scheme struct {
	PubKey  []byte
	PrivKey []byte
}

func (suite Ed25519Scheme) Sign(input []byte) []byte {
	return ed25519.Sign(suite.PrivKey, input)
}

func (suite Ed25519Scheme) Verify(publicKey []byte, msg, sig []byte) bool {
	return ed25519.Verify(suite.PubKey, msg, sig)
}

func GenerateEd25519KeyPair() ([]byte, []byte) {
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	return pk, sk
}

var scheme Ed25519Scheme

func init() {
	pk, sk := GenerateEd25519KeyPair()
	scheme.PubKey = pk
	scheme.PrivKey = sk
}

func TestGenerateSTR(t *testing.T) {

}

// scenario:
// 1st: epoch = 1
// 2nd: epoch = 3
// 3nd: epoch = 5 (latest STR)
func TestHistoryHashChain(t *testing.T) {
	currentSTR = nil
	var startupTime int64
	var epochInterval int64

	startupTime = 1
	epochInterval = 2

	key1 := "key"
	val1 := []byte("value")

	key2 := "key2"
	val2 := []byte("value2")

	key3 := "key3"
	val3 := []byte("value3")

	m1 := InitMerkleTree(treeNonce, salt, hashFunc, scheme)
	m1.InitHistory(nil, startupTime, epochInterval)
	m1.Set(key1, val1)
	m1.RecomputeHash()

	m2 := m1.clone()
	m2.UpdateHistory(nil, startupTime+epochInterval)
	m2.Set(key2, val2)
	m2.RecomputeHash()

	m3 := m2.clone()
	m3.UpdateHistory(nil, startupTime+2*epochInterval)
	m3.Set(key3, val3)
	m3.RecomputeHash()

	for i := 0; i < 2; i++ {
		str := GetSTR(startupTime + int64(i)*epochInterval)
		if str == nil {
			t.Error("Cannot get STR having epoch", startupTime+int64(i)*epochInterval)
			return
		}

		if str.epoch != startupTime+int64(i)*epochInterval {
			t.Error("Got invalid STR")
			return
		}
	}

	str := GetSTR(6)
	if str == nil {
		t.Error("Cannot get STR")
		return
	}

	if str.epoch != 5 {
		t.Error("Got invalid STR")
	}

	// check tree root of each STR is valid
	if reflect.ValueOf(m1.root).Pointer() != reflect.ValueOf(GetSTR(1).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m2.root).Pointer() != reflect.ValueOf(GetSTR(3).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
	if reflect.ValueOf(m3.root).Pointer() != reflect.ValueOf(GetSTR(5).treeRoot).Pointer() {
		t.Error("Invalid root pointer")
	}
}
