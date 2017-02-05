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
	"errors"
	"io"

	"crypto/sha512"

	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/edwards25519"
	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/extra25519"
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

type PrivateKey [PrivateKeySize]byte
type PublicKey [PublicKeySize]byte

// GenerateKey creates a public/private key pair using rnd for randomness.
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
func (pkB PublicKey) Verify(m, vrfBytes, signature []byte) bool {
	if len(vrfBytes) != Size {
		return false
	}
	if ok, vrf := pkB.verifyInteral(m, signature); ok &&
		bytes.Equal(vrfBytes, vrf[:]) {
		return true

	}
	return false
}

func calculateBv(A [32]byte, msg []byte) (Bv *edwards25519.ExtendedGroupElement) {
	/* Calculate SHA512(label(2) || A || msg) */
	buf := make([]byte, 32)
	buf[0] = 0xFD
	for count := 1; count < 32; count++ {
		buf[count] = 0xFF
	}
	buffer := bytes.NewBuffer(buf)
	buffer.Write(A[:])
	buffer.Write(msg)
	Bv = extra25519.HashToPoint(buffer.Bytes())

	return
}

func calculateBvAndV(a, Abytes [32]byte,
	msg []byte) (Bv *edwards25519.ExtendedGroupElement, V *[32]byte) {
	p3 := edwards25519.ExtendedGroupElement{}

	Bv = calculateBv(Abytes, msg)
	edwards25519.GeScalarMult(&p3, &a, Bv)
	V = new([32]byte)
	p3.ToBytes(V)
	return
}

func computeVrfFromV(Vbytes [32]byte) (vrf [32]byte) {
	var V, cV edwards25519.ExtendedGroupElement
	V.FromBytes(&Vbytes)

	edwards25519.GeDouble(&cV, &V)
	edwards25519.GeDouble(&cV, &cV)
	edwards25519.GeDouble(&cV, &cV)
	buffer := make([]byte, 32)
	buffer[0] = 0xFA // label 5
	for count := 1; count < 32; count++ {
		buffer[count] = 0xFF
	}
	var cVBytes [32]byte
	cV.ToBytes(&cVBytes)
	buf := bytes.NewBuffer(buffer)
	buf.Write(cVBytes[:])

	hash := sha512.Sum512(buf.Bytes())
	copy(vrf[:], hash[:32])
	return
}

func (sk PrivateKey) signInternal(m []byte, randr io.Reader) (signature []byte) {
	if randr == nil {
		randr = rand.Reader
	}

	// TODO check for maxMsgLen
	var a, aNeg, rB [32]byte
	var R edwards25519.ExtendedGroupElement
	var x [32]byte
	copy(x[:], sk[:])
	var edPubKey edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&edPubKey, &x)
	var A [32]byte
	edPubKey.ToBytes(&A)

	// TODO use cached public key
	// Force Edwards sign bit to zero
	signBit := (A[31] & 0x80) >> 7
	copy(a[:], sk[:32])
	edwards25519.ScNeg(&aNeg, &a)
	edwards25519.ScCMove(&a, &aNeg, int32(signBit))

	A[31] &= 0x7F
	Bv, V := calculateBvAndV(a, A, m)

	/* r = SHA512(label(3) || a || V || random(64)) */
	var Rv edwards25519.ExtendedGroupElement
	buf := make([]byte, 160)
	buf[0] = 0xFC
	for i := 1; i < 32; i++ {
		buf[i] = 0xFF
	}
	copy(buf[32:], a[:])
	copy(buf[64:], V[:])
	random := make([]byte, 64)
	if _, err := randr.Read(random); err != nil {
		panic("Couldn't read from random")
	}
	copy(buf[96:], random)

	rH := sha512.Sum512(buf[:160])

	edwards25519.ScReduce(&rB, &rH)
	edwards25519.GeScalarMultBase(&R, &rB)
	edwards25519.GeScalarMult(&Rv, &rB, Bv)

	/* h = SHA512(label(4) || A || V || R || Rv || M) */
	var Rb [32]byte
	R.ToBytes(&Rb)
	var RvB [32]byte
	Rv.ToBytes(&RvB)
	buf = append(buf, m...)
	buf[0] = 0xFB
	for i := 1; i < 32; i++ {
		buf[i] = 0xFF
	}
	copy(buf[32:], A[:])
	copy(buf[64:], V[:])
	copy(buf[96:], Rb[:])
	copy(buf[128:], RvB[:])
	//copy(buf[:160], m)
	hB := sha512.Sum512(buf[:160+len(m)])
	var h [32]byte
	edwards25519.ScReduce(&h, &hB)
	var s [32]byte
	edwards25519.ScMulAdd(&s, &h, &a, &rB)

	signature = make([]byte, ProofSize)
	copy(signature[:32], V[:])
	copy(signature[32:64], h[:])
	copy(signature[64:96], s[:])

	return
}

func (pkB PublicKey) verifyInteral(m, signature []byte) (bool, [32]byte) {
	var vrf [32]byte
	if len(signature) != ProofSize || len(pkB) != PublicKeySize {
		return false, vrf
	}
	// TODO check for max. message length
	var u edwards25519.FieldElement
	pubKey := [32]byte(pkB)
	edwards25519.FeFromBytes(&u, &pubKey)
	var strict [32]byte
	edwards25519.FeToBytes(&strict, &u)
	if !(edwards25519.FeCompare(strict, pubKey) == 0) {
		return false, vrf
	}
	var y edwards25519.FieldElement
	extra25519.FeMontgomeryXToEdwardsY(&y, &u)
	var edPubKey [32]byte
	edwards25519.FeToBytes(&edPubKey, &y)
	Bv := calculateBv(edPubKey, m)

	// verifybuf = V || h || s || m
	verifBuf := make([]byte, len(m)+160)
	copy(verifBuf, signature[:96])
	copy(verifBuf[96:], m)

	if verifBuf[63]&224 == 1 {
		return false, vrf
	}
	if verifBuf[95]&224 == 1 {
		return false, vrf
	}

	// Load -A:
	var minusA edwards25519.ExtendedGroupElement
	edwards25519.FeFromBytes(&minusA.Y, &edPubKey)
	if !minusA.FromParityAndY((edPubKey[31]>>7)^0x01, &minusA.Y) {
		return false, vrf
	}

	// Load -V
	var minusV edwards25519.ExtendedGroupElement
	var Vb [32]byte
	copy(Vb[:], signature[:32])
	edwards25519.FeFromBytes(&minusV.Y, &Vb)
	if !minusV.FromParityAndY((Vb[31]>>7)^0x01, &minusV.Y) {
		return false, vrf
	}

	// Load h, s
	var h, s [32]byte
	copy(h[:], verifBuf[32:64])
	copy(s[:], verifBuf[64:96])
	if h[31]&224 == 1 {
		return false, vrf
	} /* strict parsing of h */
	if s[31]&224 == 1 {
		return false, vrf
	} /* strict parsing of s */

	var A, cA, V, cV edwards25519.ExtendedGroupElement
	edwards25519.GeNeg(&A, minusA)
	edwards25519.GeNeg(&V, minusV)

	edwards25519.GeDouble(&cA, &A)
	edwards25519.GeDouble(&cA, &cA)
	edwards25519.GeDouble(&cA, &cA)

	edwards25519.GeDouble(&cV, &V)
	edwards25519.GeDouble(&cV, &cV)
	edwards25519.GeDouble(&cV, &cV)

	if edwards25519.GeIsNeutral(&cA) || edwards25519.GeIsNeutral(&cV) ||
		edwards25519.GeIsNeutral(Bv) {
		return false, vrf
	}

	// R = (s*B) + (h * -A))
	var R edwards25519.ProjectiveGroupElement
	edwards25519.GeDoubleScalarMultVartime(&R, &h, &minusA, &s)

	// s * Bv
	var sBv edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMult(&sBv, &s, Bv)

	// h * -V
	var hMinusV edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMult(&hMinusV, &h, &minusV)

	// Rv = (sc * Bv) + (hc * (-V))
	var Rv edwards25519.ExtendedGroupElement
	edwards25519.GeAdd(&Rv, &sBv, &hMinusV)

	// Check h == SHA512(label(4) || A || V || R || Rv || M)
	var VBytes, RBytes, RVBytes [32]byte
	V.ToBytes(&VBytes)
	R.ToBytes(&RBytes)
	Rv.ToBytes(&RVBytes)

	vrfBuf := make([]byte, 160+len(m))
	vrfBuf[0] = 0xFB // label 4
	for count := 1; count < 32; count++ {
		vrfBuf[count] = 0xFF
	}

	//copy(vrfBuf, vrfBuf))
	copy(vrfBuf[32:], edPubKey[:])
	copy(vrfBuf[64:], VBytes[:])
	copy(vrfBuf[96:], RBytes[:])
	copy(vrfBuf[128:], RVBytes[:])
	copy(vrfBuf[160:], verifBuf[96:96+len(m)])

	hCheck := sha512.Sum512(vrfBuf[:160+len(m)])

	var hCheckReduced [32]byte
	edwards25519.ScReduce(&hCheckReduced, &hCheck)

	if edwards25519.FeCompare(hCheckReduced, h) == 0 {
		// compute VRF from cV:
		var cVBytes [32]byte
		cV.ToBytes(&cVBytes)
		vrfBuf[0] = 0xFA // label 5
		copy(vrfBuf[32:], cVBytes[:])
		vrfOutput := sha512.Sum512(vrfBuf[:64])
		copy(vrf[:], vrfOutput[:32])
		// vrf = cV || hash_5(cV) (mod 2^b)
		return true, vrf
	}

	return false, vrf
}
