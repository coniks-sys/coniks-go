// Package vrf implements a verifiable random function using the Edwards form
// of Curve25519, SHA3 and the Elligator map.
//
//     E is Curve25519 (in Edwards coordinates), h is SHA512.
//     f is the elligator map (bytes->E) that covers half of E.
//     8 is the cofactor of E, the group order is 8*l for prime l.
//     Setup : the prover publicly commits to a public key (P : E)
//     H : names -> E
//         H(n) = f(h(n))^8
//     VRF : keys -> names -> vrfs
//         VRF_x(n) = h(n, H(n)^x))
//     Prove : keys -> names -> proofs
//         Prove_x(n) = tuple(c=h(n, g^r, H(n)^r), t=r-c*x, ii=H(n)^x)
//             where r = h(x, n) is used as a source of randomness
//     Check : E -> names -> vrfs -> proofs -> bool
//         Check(P, n, vrf, (c,t,ii)) = vrf == h(n, ii)
//                                     && c == h(n, g^t*P^c, H(n)^t*ii^c)
package vrf

import (
	"crypto/rand"
	"io"

	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/edwards25519"
)

const (
	PublicKeySize    = 32
	PrivateKeySize   = 64
	Size             = 32
	intermediateSize = 32
	ProofSize        = 32 + 32 + intermediateSize
)

// PrivateKey represents a Curve25519 private key.
type PrivateKey [PrivateKeySize]byte

// PublicKey represents a Curve25519 private key.
type PublicKey [PublicKeySize]byte

// GenerateKey creates a Curve25519 public/private key pair using rnd for
// randomness.
// Only the private key sk is returned (call sk.Public() the get the
// corresponding public key).
// If rnd is nil, crypto/rand is used.
func GenerateKey(rnd io.Reader) (sk PrivateKey, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	_, err = io.ReadFull(rnd, sk[:32])
	if err != nil {
		return
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64

	var ed edwards25519.ExtendedGroupElement
	var u edwards25519.FieldElement
	var x [32]byte
	copy(x[:], sk[:])

	// cache the public-key:
	edwards25519.GeScalarMultBase(&ed, &x)
	edwards25519.GeToMontX(&u, &ed)
	var pkBytes [PublicKeySize]byte
	edwards25519.FeToBytes(&pkBytes, &u)
	copy(sk[32:], pkBytes[:])

	return
}

// Public extracts the public VRF key from the underlying private-key
func (sk PrivateKey) Public() (publicKey PublicKey) {
	publicKeyB := new([PublicKeySize]byte)
	copy(publicKeyB[:], sk[32:])
	publicKey = PublicKey(*publicKeyB)
	return
}

// Compute generates the vrf value for the byte slice m using the
// underlying private key sk.
func (sk PrivateKey) Compute(m []byte) []byte {
	var a, aNeg, A [32]byte
	copy(a[:], sk[:32])
	// copy(uB[:], sk[32:64])

	// XXX use the cached public key instead:
	var x [32]byte
	copy(x[:], sk[:])
	var edPubKey edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&edPubKey, &x)
	edPubKey.ToBytes(&A)

	// Force Edwards sign bit to zero
	//copy(A[:], []byte(pkBytes))
	signBit := (A[31] & 0x80) >> 7
	copy(a[:], sk[:32])
	edwards25519.ScNeg(&aNeg, &a)
	edwards25519.ScCMove(&a, &aNeg, int32(signBit))
	A[31] &= 0x7F

	_, Vbytes := calculateBvAndV(a, A, m)
	vrfB := computeVrfFromV(*Vbytes)
	return vrfB[:]
}

// Sign returns the vrf value and a proof such that
// Verify(m, vrf, proof) == true. The vrf value is the
// same as returned by Compute(m).
func (sk PrivateKey) Sign(m []byte) (signature []byte) {
	signature = sk.signInternal(m, nil)
	return
}

// Prove returns the vrf value and a proof such that Verify(pk, m, vrf, proof)
// == true. The vrf value is the same as returned by Compute(m, sk).
func (sk PrivateKey) Prove(m []byte) (vrf, proof []byte) {
	proof = sk.Sign(m)
	var V [32]byte
	copy(V[:], proof[:32])
	v := computeVrfFromV(V)
	vrf = make([]byte, 32)
	copy(vrf, v[:])
	return
}

// Verify returns true iff vrf=Compute(m) for the sk that
// corresponds to pk.
func (pk PublicKey) Verify(m, vrfBytes, signature []byte) bool {
	if len(vrfBytes) != Size {
		return false
	}
	if ok, vrf := pk.verifyInteral(m, signature); ok &&
		bytes.Equal(vrfBytes, vrf[:]) {
		return true

	}
	return false
}
