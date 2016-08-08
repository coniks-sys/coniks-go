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

func byteSliceToCpchar(buf []byte) *C.uchar {
	ptr := unsafe.Pointer(&buf[0])
	return (*C.uchar)(ptr)
}

func testVerifyVrf(t *testing.T) {
	pk, sk, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	alice := []byte("alice")
	aliceVRF, aliceProof := sk.Prove(alice)
	if v := C.testVerifyVrf(byteSliceToCpchar(pk[:]), C.int(len(pk)),
		byteSliceToCpchar(alice), C.int(len(alice)),
		byteSliceToCpchar(aliceVRF), C.int(len(aliceVRF)),
		byteSliceToCpchar(aliceProof), C.int(len(aliceProof))); v != 1 {
		t.Error("cgoVrfVerify failed")
	}
}

func testVerifySignature(t *testing.T) {
	key, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")
	sig := key.Sign(message)

	pk, ok := key.Public()
	if !ok {
		t.Errorf("bad PK?")
	}

	if v := C.testVerifySignature(byteSliceToCpchar(pk), C.int(len(pk)),
		byteSliceToCpchar(message), C.int(len(message)),
		byteSliceToCpchar(sig), C.int(len(sig))); v != 1 {
		t.Error("cgoVerifySignature failed")
	}
}

func testVerifyHashChain(t *testing.T) {
	signKey, err := sign.GenerateKey()
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

	if v := C.testVerifyHashChain(byteSliceToCpchar(str1.PreviousSTRHash), C.int(len(str1.PreviousSTRHash)),
		byteSliceToCpchar(str0.Signature), C.int(len(str0.Signature))); v != 1 {
		t.Error("cgoVerifyHashChain failed")
	}
}

func testVerifyAuthPath(t *testing.T) {
	signKey, err := sign.GenerateKey()
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
	if proof.Leaf.IsEmpty() {
		isLeafEmpty = 1
	}
	if v := C.testVerifyAuthPath(byteSliceToCpchar(pad.LatestSTR().Root()), C.int(len(pad.LatestSTR().Root())),
		byteSliceToCpchar(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCpchar(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level()),
		byteSliceToCpchar(proof.Leaf.Index()), C.int(len(proof.Leaf.Index())),
		byteSliceToCpchar(proof.Leaf.Commitment()), C.int(len(proof.Leaf.Commitment())),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of inclusion failed")
	}

	// proof of absence
	proof, err = pad.Lookup("123")
	if err != nil {
		t.Fatal(err)
	}

	isLeafEmpty = 0
	if proof.Leaf.IsEmpty() {
		isLeafEmpty = 1
	}
	if v := C.testVerifyAuthPath(byteSliceToCpchar(pad.LatestSTR().Root()), C.int(len(pad.LatestSTR().Root())),
		byteSliceToCpchar(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCpchar(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level()),
		byteSliceToCpchar(proof.Leaf.Index()), C.int(len(proof.Leaf.Index())),
		nil, C.int(0),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of absence failed")
	}
}

func testVerifyProofOfAbsenceSamePrefix(t *testing.T) {
	signKey, err := sign.GenerateKey()
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
	if proof.Leaf.IsEmpty() {
		isLeafEmpty = 1
	}
	if v := C.testVerifyAuthPath(byteSliceToCpchar(pad.LatestSTR().Root()), C.int(len(pad.LatestSTR().Root())),
		byteSliceToCpchar(proof.TreeNonce), C.int(len(proof.TreeNonce)),
		byteSliceToCpchar(proof.LookupIndex), C.int(len(proof.LookupIndex)),
		(**C.uchar)(unsafe.Pointer(&proof.PrunedTree[0][0])), C.int(len(proof.PrunedTree)), C.int(len(proof.PrunedTree[0])),
		C.int(proof.Leaf.Level()),
		byteSliceToCpchar(proof.Leaf.Index()), C.int(len(proof.Leaf.Index())),
		byteSliceToCpchar(proof.Leaf.Commitment()), C.int(len(proof.Leaf.Commitment())),
		C.int(isLeafEmpty)); v != 1 {
		t.Error("Verify proof of absence failed")
	}
}
