package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

func computeLeafHash(ap *AuthenticationPath) (leafHash []byte) {
	leaf := ap.Leaf
	if !leaf.IsEmpty() {
		// user leaf node
		leafHash = crypto.Digest(
			[]byte{LeafIdentifier},                // K_leaf
			[]byte(ap.TreeNonce),                  // K_n
			[]byte(leaf.Index()),                  // i
			[]byte(util.IntToBytes(leaf.Level())), // l
			[]byte(leaf.Commitment()),             // commit(key|| value)
		)
	} else {
		// empty leaf node
		leafHash = crypto.Digest(
			[]byte{EmptyBranchIdentifier},         // K_empty
			[]byte(ap.TreeNonce),                  // K_n
			[]byte(leaf.Index()),                  // i
			[]byte(util.IntToBytes(leaf.Level())), // l
		)
	}
	return
}

func authPathHash(ap *AuthenticationPath) []byte {
	prunedHashes := ap.PrunedTree
	hash := computeLeafHash(ap)
	depth := ap.Leaf.Level() - 1
	indexBits := util.ToBits(ap.Leaf.Index())
	for depth > -1 {
		if indexBits[depth] { // right child
			hash = crypto.Digest(prunedHashes[depth], hash)
		} else {
			hash = crypto.Digest(hash, prunedHashes[depth])
		}
		depth -= 1
	}
	return hash
}

func verifyProof(t *testing.T, ap *AuthenticationPath, treeHash []byte, key string) {
	// step 1. vrf_verify(i, alice) == true
	// we probably want to use vrf.Verify() here instead
	if !bytes.Equal(vrf.Compute([]byte(key), vrfPrivKey1), ap.LookupIndex) {
		t.Error("VRF verify returns false")
	}

	// step 2. verify if it's a proof of inclusion/proof of absence
	if bytes.Equal(ap.Leaf.Index(), ap.LookupIndex) {
		// proof of inclusion
		// make sure we got a userLeafNode
		if _, ok := ap.Leaf.(*userLeafNode); !ok {
			t.Error("Expect a user leaf node in returned path")
		}
	} else {
		// proof of absence
		// check if i and j match in the first l bits
		indexBits := util.ToBits(ap.Leaf.Index())
		lookupIndexBits := util.ToBits(ap.LookupIndex)

		for i := 0; i < ap.Leaf.Level(); i++ {
			if indexBits[i] != lookupIndexBits[i] {
				t.Error("Invalid proof of absence. Expect indices share the same prefix",
					"lookup index: ", indexBits[:ap.Leaf.Level()],
					"leaf index: ", lookupIndexBits[:ap.Leaf.Level()])
			}
		}
	}

	// step 3. Verify the auth path of the returned leaf
	hash := authPathHash(ap)
	if !bytes.Equal(treeHash, hash) {
		t.Fatal("Invalid proof")
	}
}

func TestVerifyProof(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := vrf.Compute([]byte(key1), vrfPrivKey1)
	val1 := []byte("value1")
	key2 := "key2"
	index2 := vrf.Compute([]byte(key2), vrfPrivKey1)
	val2 := []byte("value2")
	key3 := "key3"
	index3 := vrf.Compute([]byte(key3), vrfPrivKey1)
	val3 := []byte("value3")

	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(index2, key2, val2); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(index3, key3, val3); err != nil {
		t.Fatal(err)
	}

	m.recomputeHash()

	ap1 := m.Get(index1)
	if ap1.Leaf.Value() == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	ap2 := m.Get(index2)
	if ap2.Leaf.Value() == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	ap3 := m.Get(index3)
	if ap3.Leaf.Value() == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// proof of inclusion
	proof := m.Get(index3)
	verifyProof(t, proof, m.hash, key3)

	// proof of absence
	absentIndex := vrf.Compute([]byte("123"), vrfPrivKey1)
	proof = m.Get(absentIndex) // shares the same prefix with an empty node
	verifyProof(t, proof, m.hash, "123")
	if _, ok := proof.Leaf.(*emptyNode); !ok {
		t.Error("Invalid proof of absence. Expect an empty node in returned path")
	}
}

func TestVerifyProofSamePrefix(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	index1 := vrf.Compute([]byte(key1), vrfPrivKey1)
	val1 := []byte("value1")
	if err := m.Set(index1, key1, val1); err != nil {
		t.Fatal(err)
	}
	m.recomputeHash()
	absentIndex := vrf.Compute([]byte("a"), vrfPrivKey1)
	proof := m.Get(absentIndex) // shares the same prefix with leaf node key1
	// assert these indices share the same prefix in the first bit
	if !bytes.Equal(util.ToBytes(util.ToBits(index1)[:proof.Leaf.Level()]),
		util.ToBytes(util.ToBits(absentIndex)[:proof.Leaf.Level()])) {
		t.Fatal("Expect these indices share the same prefix in the first bit")
	}
	verifyProof(t, proof, m.hash, "a")
}
