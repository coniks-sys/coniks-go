// Package vrf implements a verifiable random function using the Edwards form
// of Curve25519, SHA3 and the Elligator map.
//
//     E is Curve25519 (in Edwards coordinates), h is SHA3.
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
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/edwards25519"
	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"
)

const (
	PublicKeySize    = 32
	PrivateKeySize   = 64
	Size             = 32
	intermediateSize = 32
	ProofSize        = 32 + 32 + intermediateSize
)

var (
	ErrGetPubKey = errors.New("[vrf] Couldn't get corresponding public-key from private-key")
)

type PrivateKey []byte
type PublicKey []byte

// GenerateKey creates a public/private key pair using rnd for randomness.
// If rnd is nil, crypto/rand is used.
func GenerateKey(rnd io.Reader) (sk PrivateKey, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	sk = make([]byte, 64)
	_, err = io.ReadFull(rnd, sk[:32])
	if err != nil {
		return
	}
	x, _ := sk.expandSecret()

	var pkP edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&pkP, x)
	var pkBytes [PublicKeySize]byte
	pkP.ToBytes(&pkBytes)

	copy(sk[32:], pkBytes[:])
	return
}

// Public extracts the public VRF key from the underlying private-key
// and returns a boolean indicating if the operation was successful.
func (sk PrivateKey) Public() (PublicKey, bool) {
	pk, ok := ed25519.PrivateKey(sk).Public().(ed25519.PublicKey)
	return PublicKey(pk), ok
}

func (sk PrivateKey) expandSecret() (x, skhr *[32]byte) {
	x, skhr = new([32]byte), new([32]byte)
	hash := sha3.NewShake256()
	hash.Write(sk[:32])
	hash.Read(x[:])
	hash.Read(skhr[:])
	x[0] &= 248
	x[31] &= 127
	x[31] |= 64
	return
}

// Compute generates the vrf value for the byte slice m using the
// underlying private key sk.
func (sk PrivateKey) Compute(m []byte) []byte {
	x, _ := sk.expandSecret()
	var ii edwards25519.ExtendedGroupElement
	var iiB [32]byte
	edwards25519.GeScalarMult(&ii, x, hashToCurve(m))
	ii.ToBytes(&iiB)

	hash := sha3.NewShake256()
	hash.Write(iiB[:]) // const length: Size
	hash.Write(m)
	var vrf [Size]byte
	hash.Read(vrf[:])
	return vrf[:]
}

func hashToCurve(m []byte) *edwards25519.ExtendedGroupElement {
	// H(n) = (f(h(n))^8)
	var hmb [32]byte
	sha3.ShakeSum256(hmb[:], m)
	var hm edwards25519.ExtendedGroupElement
	extra25519.HashToEdwards(&hm, &hmb)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	edwards25519.GeDouble(&hm, &hm)
	return &hm
}

// Prove returns the vrf value and a proof such that
// Verify(m, vrf, proof) == true. The vrf value is the
// same as returned by Compute(m).
func (sk PrivateKey) Prove(m []byte) (vrf, proof []byte) {
	x, skhr := sk.expandSecret()
	var cH, rH [64]byte
	var r, c, minusC, t, grB, hrB, iiB [32]byte
	var ii, gr, hr edwards25519.ExtendedGroupElement

	hm := hashToCurve(m)
	edwards25519.GeScalarMult(&ii, x, hm)
	ii.ToBytes(&iiB)

	hash := sha3.NewShake256()
	hash.Write(skhr[:])
	hash.Write(sk[32:]) // public key, as in ed25519
	hash.Write(m)
	hash.Read(rH[:])
	hash.Reset()
	edwards25519.ScReduce(&r, &rH)

	edwards25519.GeScalarMultBase(&gr, &r)
	edwards25519.GeScalarMult(&hr, &r, hm)
	gr.ToBytes(&grB)
	hr.ToBytes(&hrB)

	hash.Write(grB[:])
	hash.Write(hrB[:])
	hash.Write(m)
	hash.Read(cH[:])
	hash.Reset()
	edwards25519.ScReduce(&c, &cH)

	edwards25519.ScNeg(&minusC, &c)
	edwards25519.ScMulAdd(&t, x, &minusC, &r)

	proof = make([]byte, ProofSize)
	copy(proof[:32], c[:])
	copy(proof[32:64], t[:])
	copy(proof[64:96], iiB[:])

	hash.Write(iiB[:]) // const length: Size
	hash.Write(m)
	vrf = make([]byte, Size)
	hash.Read(vrf[:])
	return
}

// Verify returns true iff vrf=Compute(m) for the sk that
// corresponds to pk.
func (pkBytes PublicKey) Verify(m, vrfBytes, proof []byte) bool {
	if len(proof) != ProofSize || len(vrfBytes) != Size || len(pkBytes) != PublicKeySize {
		return false
	}
	var pk, c, cRef, t, vrf, iiB, ABytes, BBytes [32]byte
	copy(vrf[:], vrfBytes)
	copy(pk[:], pkBytes[:])
	copy(c[:32], proof[:32])
	copy(t[:32], proof[32:64])
	copy(iiB[:], proof[64:96])

	hash := sha3.NewShake256()
	hash.Write(iiB[:]) // const length
	hash.Write(m)
	var hCheck [Size]byte
	hash.Read(hCheck[:])
	if !bytes.Equal(hCheck[:], vrf[:]) {
		return false
	}
	hash.Reset()

	var P, B, ii, iic edwards25519.ExtendedGroupElement
	var A, hmtP, iicP edwards25519.ProjectiveGroupElement
	if !P.FromBytesBaseGroup(&pk) {
		return false
	}
	if !ii.FromBytesBaseGroup(&iiB) {
		return false
	}
	edwards25519.GeDoubleScalarMultVartime(&A, &c, &P, &t)
	A.ToBytes(&ABytes)

	hm := hashToCurve(m)
	edwards25519.GeDoubleScalarMultVartime(&hmtP, &t, hm, &[32]byte{})
	edwards25519.GeDoubleScalarMultVartime(&iicP, &c, &ii, &[32]byte{})
	iicP.ToExtended(&iic)
	hmtP.ToExtended(&B)
	edwards25519.GeAdd(&B, &B, &iic)
	B.ToBytes(&BBytes)

	var cH [64]byte
	hash.Write(ABytes[:]) // const length
	hash.Write(BBytes[:]) // const length
	hash.Write(m)
	hash.Read(cH[:])
	edwards25519.ScReduce(&cRef, &cH)
	return cRef == c
}
