package main

import "C"

import (
	"bytes"
	"unsafe"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// main is required to build a shared library, but does nothing
func main() {}

//export cgoVerifySignature
func cgoVerifySignature(pk unsafe.Pointer, pkSize C.int,
	message unsafe.Pointer, size C.int,
	sig unsafe.Pointer, sigSize C.int) C.int {
	if int(pkSize) != sign.PublicKeySize ||
		int(sigSize) != sign.SignatureSize {
		return 0
	}
	pkBytes := C.GoBytes(pk, pkSize)
	messageBytes := C.GoBytes(message, size)
	sigBytes := C.GoBytes(sig, sigSize)
	key := sign.PublicKey(pkBytes)
	if key.Verify(messageBytes, sigBytes) {
		return 1
	}
	return 0
}

//export cgoVerifyVrf
func cgoVerifyVrf(pk unsafe.Pointer, pkSize C.int,
	m unsafe.Pointer, size C.int,
	index unsafe.Pointer, indexSize C.int,
	proof unsafe.Pointer, proofSize C.int) C.int {
	if int(pkSize) != vrf.PublicKeySize ||
		int(indexSize) != vrf.Size ||
		int(proofSize) != vrf.ProofSize {
		return 0
	}
	pkBytes := C.GoBytes(pk, pkSize)
	mBytes := C.GoBytes(m, size)
	vrfBytes := C.GoBytes(index, indexSize)
	proofBytes := C.GoBytes(proof, proofSize)
	var key vrf.PublicKey
	copy(key[:], pkBytes)
	if key.Verify(mBytes, vrfBytes, proofBytes) {
		return 1
	}
	return 0
}

//export cgoVerifyHashChain
func cgoVerifyHashChain(prevHash unsafe.Pointer, hashSize C.int,
	savedStrSig unsafe.Pointer, sigSize C.int) C.int {
	if int(hashSize) != crypto.HashSizeByte ||
		int(sigSize) != sign.SignatureSize {
		return 0
	}
	prevHashBytes := C.GoBytes(prevHash, hashSize)
	sigBytes := C.GoBytes(savedStrSig, sigSize)
	strHash := crypto.Digest(sigBytes)
	if bytes.Equal(prevHashBytes, strHash) {
		return 1
	}
	return 0
}

//export cgoVerifyAuthPath
//must call cgoVerifyVrf first to verify the returned vrf index.
func cgoVerifyAuthPath(treeHash unsafe.Pointer, treeHashSize C.int,
	treeNonce unsafe.Pointer, treeNonceSize C.int,
	lookupIndex unsafe.Pointer, indexSize C.int,
	prunedHashes unsafe.Pointer, prunedSize C.int, hashSize C.int,
	leafLevel C.int,
	leafIndex unsafe.Pointer, leafIndexSize C.int,
	leafCommitment unsafe.Pointer, commitmentSize C.int,
	isLeafEmpty C.int) C.int {

	if int(treeHashSize) != crypto.HashSizeByte ||
		int(treeNonceSize) != crypto.HashSizeByte ||
		int(indexSize) != vrf.Size ||
		int(hashSize) != crypto.HashSizeByte ||
		int(prunedSize) < 1 {
		return 0
	}
	if int(isLeafEmpty) != 1 && // user leaf node
		(int(leafIndexSize) != vrf.Size ||
			int(commitmentSize) != crypto.HashSizeByte) {
		return 0
	}

	th := C.GoBytes(treeHash, treeHashSize)
	tn := C.GoBytes(treeNonce, treeNonceSize)
	li := C.GoBytes(lookupIndex, indexSize)
	leafi := C.GoBytes(leafIndex, leafIndexSize)
	leafc := C.GoBytes(leafCommitment, commitmentSize)

	buf := C.GoBytes(prunedHashes, prunedSize*hashSize)
	pt := make([][crypto.HashSizeByte]byte, 0, prunedSize)
	for i := 0; i < int(prunedSize); i++ {
		var arr [crypto.HashSizeByte]byte
		copy(arr[:], buf[:hashSize])
		pt = append(pt, arr)
		buf = buf[hashSize:]
	}

	ap := new(merkletree.AuthenticationPath)
	ap.TreeNonce = tn
	ap.LookupIndex = li
	ap.PrunedTree = pt

	if merkletree.VerifyAuthPath(ap, leafi, leafc, int(leafLevel), int(isLeafEmpty) == 1, th) {
		return 1
	}
	return 0
}