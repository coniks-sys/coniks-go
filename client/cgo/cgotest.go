package main

/*
int testVerifyVrf(unsigned char *pk, int pkSize,
    unsigned char *m, int mSize,
    unsigned char *index, int indexSize,
    unsigned char *proof, int proofSize) {
    return cgoVerifyVrf(pk, pkSize, m, mSize, index, indexSize, proof, proofSize);
}

int testVerifySignature(
    unsigned char *pk, int pkSize,
    unsigned char *m, int mSize,
    unsigned char *sig, int sigSize) {
    return cgoVerifySignature(pk, pkSize, m, mSize, sig, sigSize);
}

int testVerifyHashChain(
	unsigned char *prevHash, int hashSize,
    unsigned char *strSig, int sigSize) {
    return cgoVerifyHashChain(prevHash, hashSize, strSig, sigSize);
}

int testVerifyAuthPath(
    unsigned char *treeHash, int treeHashSize,
    unsigned char *treeNonce, int treeNonceSize,
    unsigned char *lookupIndex, int lookupIndexSize,
    unsigned char **prunedTree, int prunedTreeSize, int hashSize,
    int leafLevel,
    unsigned char *leafIndex, int leafIndexSize,
    unsigned char *leafCommitment, int leafCommitmentSize,
    int isLeafEmpty) {
    return cgoVerifyAuthPath(treeHash, treeHashSize,
        treeNonce, treeNonceSize,
        lookupIndex, lookupIndexSize,
        prunedTree, prunedTreeSize, hashSize,
        leafLevel,
        leafIndex, leafIndexSize,
        leafCommitment, leafCommitmentSize,
        isLeafEmpty);
}

int testVerifyCommitment(
	unsigned char *salt, int saltSize,
	char *key, int keySize,
	unsigned char *value, int valueSize,
	unsigned char *commitment, int commitmentSize)  {
	return cgoVerifyCommitment(salt, saltSize,
		key, keySize,
		value, valueSize,
		commitment, commitmentSize);
}

#cgo CFLAGS: -Wno-implicit-function-declaration
*/
import "C"
import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

func byteSliceToCucharPtr(buf []byte) *C.uchar {
	ptr := unsafe.Pointer(&buf[0])
	return (*C.uchar)(ptr)
}

func byteSliceToCcharPtr(buf []byte) *C.char {
	ptr := unsafe.Pointer(&buf[0])
	return (*C.char)(ptr)
}

func testVerifyVrf(t *testing.T) {
	pk, sk, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := []byte("alice")
	aliceVRF, aliceProof := sk.Prove(alice)
	if v := C.testVerifyVrf(byteSliceToCucharPtr(pk[:]), C.int(len(pk)),
		byteSliceToCucharPtr(alice), C.int(len(alice)),
		byteSliceToCucharPtr(aliceVRF), C.int(len(aliceVRF)),
		byteSliceToCucharPtr(aliceProof), C.int(len(aliceProof))); v != 1 {
		t.Error("cgoVrfVerify failed")
	}
}

func testVerifySignature(t *testing.T) {
	key, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig := key.Sign(message)

	pk, ok := key.Public()
	if !ok {
		t.Errorf("bad PK?")
	}

	if v := C.testVerifySignature(byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCucharPtr(message), C.int(len(message)),
		byteSliceToCucharPtr(sig), C.int(len(sig))); v != 1 {
		t.Error("cgoVerifySignature failed")
	}
}

func testVerifyHashChain(t *testing.T) {
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, vrfPrivKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pad, err := merkletree.NewPAD(merkletree.NewPolicies(2, vrfPrivKey), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	key1 := "key1"
	val1 := []byte("value1")

	if err := pad.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)
	str0 := pad.GetSTR(0)
	str1 := pad.GetSTR(1)

	if v := C.testVerifyHashChain(byteSliceToCucharPtr(str1.PreviousSTRHash), C.int(len(str1.PreviousSTRHash)),
		byteSliceToCucharPtr(str0.Signature), C.int(len(str0.Signature))); v != 1 {
		t.Error("cgoVerifyHashChain failed")
	}
}

func testVerifyAuthPath(t *testing.T) {
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, vrfPrivKey, err := vrf.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		t.Fatal(err)
	}
	pad, err := merkletree.NewPAD(merkletree.NewPolicies(2, vrfPrivKey), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")
	key3 := "key3"
	val3 := []byte("value3")

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

	// proof of inclusion
	proof, err := pad.Lookup(key3)
	if err != nil {
		t.Fatal(err)
	}

	isLeafEmpty := 0
	if proof.Leaf.IsEmpty {
		isLeafEmpty = 1
	}
	// verify commitment
	if v := C.testVerifyCommitment(byteSliceToCucharPtr(proof.Leaf.Salt), C.int(len(proof.Leaf.Salt)),
		byteSliceToCcharPtr([]byte(key3)), C.int(len(key3)),
		byteSliceToCucharPtr(proof.Leaf.Value), C.int(len(proof.Leaf.Value)),
		byteSliceToCucharPtr(proof.Leaf.Commitment), C.int(len(proof.Leaf.Commitment))); v != 1 {
		t.Fatal("Verify commitment failed")
	}

	if v := C.testVerifyAuthPath(byteSliceToCucharPtr(pad.LatestSTR().TreeHash), C.int(len(pad.LatestSTR().TreeHash)),
		byteSliceToCucharPtr(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCucharPtr(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level),
		byteSliceToCucharPtr(proof.Leaf.Index), C.int(len(proof.Leaf.Index)),
		byteSliceToCucharPtr(proof.Leaf.Commitment), C.int(len(proof.Leaf.Commitment)),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of inclusion failed")
	}

	// proof of absence
	proof, err = pad.Lookup("123")
	if err != nil {
		t.Fatal(err)
	}

	isLeafEmpty = 0
	if proof.Leaf.IsEmpty {
		isLeafEmpty = 1
	}
	if v := C.testVerifyAuthPath(byteSliceToCucharPtr(pad.LatestSTR().TreeHash), C.int(len(pad.LatestSTR().TreeHash)),
		byteSliceToCucharPtr(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCucharPtr(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level),
		byteSliceToCucharPtr(proof.Leaf.Index), C.int(len(proof.Leaf.Index)),
		nil, C.int(0),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of absence failed")
	}
}

func testVerifyProofOfAbsenceSamePrefix(t *testing.T) {
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, vrfPrivKey, err := vrf.GenerateKey(bytes.NewReader(
		[]byte("deterministic tests need 256 bit")))
	if err != nil {
		t.Fatal(err)
	}
	pad, err := merkletree.NewPAD(merkletree.NewPolicies(2, vrfPrivKey), signKey, 10)
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	val1 := []byte("value1")

	if err := pad.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	pad.Update(nil)

	// proof of inclusion
	proof, err := pad.Lookup("a")
	if err != nil {
		t.Fatal(err)
	}

	isLeafEmpty := 0
	if proof.Leaf.IsEmpty {
		isLeafEmpty = 1
	}
	if v := C.testVerifyAuthPath(byteSliceToCucharPtr(pad.LatestSTR().TreeHash), C.int(len(pad.LatestSTR().TreeHash)),
		byteSliceToCucharPtr(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCucharPtr(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level),
		byteSliceToCucharPtr(proof.Leaf.Index), C.int(len(proof.Leaf.Index)),
		byteSliceToCucharPtr(proof.Leaf.Commitment), C.int(len(proof.Leaf.Commitment)),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of absence failed")
	}
}
