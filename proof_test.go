package merkletree

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
	"github.com/coniks-sys/libmerkleprefixtree-go/internal"
)

func computeLeafHash(ap *AuthenticationPath) (leafHash []byte) {
	leaf := ap.Leaf()
	if !leaf.IsEmpty() {
		// user leaf node
		leafHash = crypto.Digest(
			[]byte{LeafIdentifier},              // K_leaf
			[]byte(ap.TreeNonce()),              // K_n
			[]byte(ap.Index()),                  // i
			[]byte(util.IntToBytes(ap.Level())), // l
			[]byte(leaf.Commitment()),           // commit(key|| value)
		)
	} else {
		// empty leaf node
		leafHash = crypto.Digest(
			[]byte{EmptyBranchIdentifier},       // K_empty
			[]byte(ap.TreeNonce()),              // K_n
			[]byte(ap.Index()),                  // i
			[]byte(util.IntToBytes(ap.Level())), // l
		)
	}
	return
}

func authPathHash(ap *AuthenticationPath) []byte {
	prunedHashes := ap.PrunedTree()
	hash := computeLeafHash(ap)
	depth := ap.level - 1
	indexBits := util.ToBits(ap.Index())
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
	hash := authPathHash(ap)
	if !bytes.Equal(treeHash, hash) {
		t.Error("Invalid proof")
	}

	// step 1. Verify the auth path of the returned leaf
	if bytes.Equal(ap.Index(), ap.LookupIndex()) {
		// proof of inclusion
		// make sure we got a userLeafNode
		if _, ok := ap.Leaf().(*userLeafNode); !ok {
			t.Error("Expect a user leaf node in returned path")
		}
	} else {
		// proof of absence
		// step 2. Check that where i and j differ is at bit l
		indexBits := util.ToBits(ap.Index())
		lookupIndexBits := util.ToBits(ap.LookupIndex())

		for i := 0; i < ap.Level(); i++ {
			if indexBits[i] != lookupIndexBits[i] {
				t.Error("Invalid proof of absence. Expect indecies share the same prefix",
					"lookup index: ", indexBits[:ap.Level()],
					"leaf index: ", lookupIndexBits[:ap.Level()])
			}
		}
		if indexBits[ap.Level()+1] == lookupIndexBits[ap.Level()+1] {
			t.Error("Invalid proof of absence. Expect indecies differ is at bit", ap.Level()+1)
		}

		// step 3. vrf_verify(i, alice) == true
		if !bytes.Equal(computePrivateIndex(key), ap.LookupIndex()) {
			t.Error("VRF verify returns false")
		}
	}
}

func TestVerifyProof(t *testing.T) {
	m, err := NewMerkleTree()
	if err != nil {
		t.Fatal(err)
	}

	key1 := "key1"
	val1 := []byte("value1")
	key2 := "key2"
	val2 := []byte("value2")
	key3 := "key3"
	val3 := []byte("value3")

	if err := m.Set(key1, val1); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key2, val2); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(key3, val3); err != nil {
		t.Fatal(err)
	}

	m.recomputeHash()

	n1, _ := m.Get(key1)
	if n1 == nil {
		t.Error("Cannot find key:", key1)
		return
	}
	n2, _ := m.Get(key2)
	if n2 == nil {
		t.Error("Cannot find key:", key2)
		return
	}
	n3, _ := m.Get(key3)
	if n3 == nil {
		t.Error("Cannot find key:", key3)
		return
	}

	// proof of inclusion
	_, proof := m.Get(key3)
	verifyProof(t, proof, m.GetHash(), key3)
	hash := authPathHash(proof)
	if !bytes.Equal(m.GetHash(), hash) {
		t.Error("Invalid proof of inclusion")
	}

	// proof of absence
	_, proof = m.Get("123") // shares the same prefix with an empty node
	verifyProof(t, proof, m.GetHash(), "123")
	authPathHash(proof)
	if _, ok := proof.Leaf().(*emptyNode); !ok {
		t.Error("Invalid proof of absence. Expect an empty node in returned path")
	}

	_, proof = m.Get("key4") // shares the same prefix with leaf node n2
	verifyProof(t, proof, m.GetHash(), "key4")
	authPathHash(proof)
	if _, ok := proof.Leaf().(*userLeafNode); !ok {
		t.Error("Invalid proof of absence. Expect a user leaf node in returned path")
	}
}
