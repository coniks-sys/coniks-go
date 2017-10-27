package merkletree

import (
	"bytes"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

type mockTest struct {
	key   string
	value []byte
	index []byte
	want  ProofType
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = rand.NewSource(time.Now().UnixNano())

// Credit: https://stackoverflow.com/a/31832326
func RandStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

var N uint64 = 3 // number of inclusions.

func setup(t *testing.T) (*MerkleTree, []*mockTest) {
	m := newTestTree(t)

	tuple := []*mockTest{}
	for i := uint64(0); i < uint64(N); i++ {
		key := keyPrefix + strconv.FormatUint(i, 10)
		val := append(valuePrefix, byte(i))
		index := crypto.StaticVRF(t).Compute([]byte(key))
		if err := m.Set(index, key, val); err != nil {
			t.Fatal(err)
		}
		tuple = append(tuple, &mockTest{key, val, index, ProofOfInclusion})
	}

	sharedPrefix := tuple[0].index
	var absentKey string
	var absentIndex []byte
	for {
		absentKey = RandStringBytesMaskImprSrc(3)
		absentIndex = crypto.StaticVRF(t).Compute([]byte(absentKey))
		proof := m.Get(absentIndex)
		// assert these indices share the same prefix in the first bit
		if bytes.Equal(utils.ToBytes(utils.ToBits(sharedPrefix)[:proof.Leaf.Level]),
			utils.ToBytes(utils.ToBits(absentIndex)[:proof.Leaf.Level])) {
			break
		}
	}

	tuple = append(tuple, &mockTest{absentKey, nil, absentIndex, ProofOfAbsence})
	m.recomputeHash()
	return m, tuple
}

func TestVerifyProof(t *testing.T) {
	m, tests := setup(t)

	for _, tt := range tests {
		proof := m.Get(tt.index)
		if got, want := proof.ProofType(), tt.want; got != want {
			t.Error("TestVerifyProof() failed with tuple(", tt.key, tt.value, ")")
		}
		if proof.Verify([]byte(tt.key), tt.value, m.hash) != nil {
			t.Error("TestVerifyProof() failed with tuple(", tt.key, tt.value, ")")
		}
	}
}

func TestProofVerificationErrors(t *testing.T) {
	m, tuple := setup(t)

	index, key, value := tuple[0].index, tuple[0].key, tuple[0].value

	// ProofOfInclusion
	// assert proof of inclusion
	proof1 := m.Get(index)
	if proof1.ProofType() != ProofOfInclusion {
		t.Fatal("Expect a proof of inclusion")
	}
	// - ErrBindingsDiffer
	proof1.Leaf.Value[0] += 1
	if err := proof1.Verify([]byte(key), value, m.hash); err != ErrBindingsDiffer {
		t.Error("Expect", ErrBindingsDiffer, "got", err)
	}
	// - ErrUnverifiableCommitment
	proof1.Leaf.Value[0] -= 1
	proof1.Leaf.Commitment.Salt[0] += 1
	if err := proof1.Verify([]byte(key), value, m.hash); err != ErrUnverifiableCommitment {
		t.Error("Expect", ErrUnverifiableCommitment, "got", err)
	}
	// ErrUnequalTreeHashes
	hash := append([]byte{}, m.hash...)
	hash[0] += 1
	proof1.Leaf.Commitment.Salt[0] -= 1
	if err := proof1.Verify([]byte(key), value, hash); err != ErrUnequalTreeHashes {
		t.Error("Expect", ErrUnequalTreeHashes, "got", err)
	}

	// ProofOfAbsence
	index, key, value = tuple[N].index, tuple[N].key, tuple[N].value
	proof2 := m.Get(index) // shares the same prefix with leaf node key1
	// assert proof of absence
	if proof2.ProofType() != ProofOfAbsence {
		t.Fatal("Expect a proof of absence")
	}
	// - ErrBindingsDiffer
	proof2.Leaf.Value = make([]byte, 1)
	if err := proof2.Verify([]byte(key), value, m.hash); err != ErrBindingsDiffer {
		t.Error("Expect", ErrBindingsDiffer, "got", err)
	}
	// - ErrIndicesMismatch
	proof2.Leaf.Value = nil
	proof2.Leaf.Index[0] &= 0x01
	if err := proof2.Verify([]byte(key), value, m.hash); err != ErrIndicesMismatch {
		t.Error("Expect", ErrIndicesMismatch, "got", err)
	}
}
