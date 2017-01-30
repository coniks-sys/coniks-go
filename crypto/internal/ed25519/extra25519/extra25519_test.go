// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package extra25519

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"testing"

	"encoding/hex"
	"fmt"
	"github.com/coniks-sys/coniks-go/crypto/internal/ed25519/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

func TestCurve25519Conversion(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	var pubBytes [32]byte
	copy(pubBytes[:], public)
	var privBytes [64]byte
	copy(privBytes[:], private)

	var curve25519Public, curve25519Public2, curve25519Private [32]byte
	PrivateKeyToCurve25519(&curve25519Private, &privBytes)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	if !PublicKeyToCurve25519(&curve25519Public2, &pubBytes) {
		t.Fatalf("PublicKeyToCurve25519 failed")
	}

	if !bytes.Equal(curve25519Public[:], curve25519Public2[:]) {
		t.Errorf("Values didn't match: curve25519 produced %x, conversion produced %x", curve25519Public[:], curve25519Public2[:])
	}
}

func TestHashNoCollisions(t *testing.T) {
	type intpair struct {
		i int
		j uint
	}
	rainbow := make(map[[32]byte]intpair)
	N := 25
	if testing.Short() {
		N = 3
	}
	var h [32]byte
	// NOTE: hash values 0b100000000000... and 0b00000000000... both map to
	// the identity. this is a core part of the elligator function and not a
	// collision we need to worry about because an attacker would need to find
	// the preimages of these hashes to exploit it.
	h[0] = 1
	for i := 0; i < N; i++ {
		for j := uint(0); j < 257; j++ {
			if j < 256 {
				h[j>>3] ^= byte(1) << (j & 7)
			}

			var P edwards25519.ExtendedGroupElement
			HashToEdwards(&P, &h)
			var p [32]byte
			P.ToBytes(&p)
			if c, ok := rainbow[p]; ok {
				t.Fatalf("found collision: (%d, %d) and (%d, %d)", i, j, c.i, c.j)
			}
			rainbow[p] = intpair{i, j}

			if j < 256 {
				h[j>>3] ^= byte(1) << (j & 7)
			}
		}
		hh := sha512.Sum512(h[:]) // this package already imports sha512
		copy(h[:], hh[:])
	}
}

func TestElligator(t *testing.T) {
	var publicKey, publicKey2, publicKey3, representative, privateKey [32]byte

	for i := 0; i < 1000; i++ {
		rand.Reader.Read(privateKey[:])

		if !ScalarBaseMult(&publicKey, &representative, &privateKey) {
			continue
		}
		RepresentativeToPublicKey(&publicKey2, &representative)
		if !bytes.Equal(publicKey[:], publicKey2[:]) {
			t.Fatal("The resulting public key doesn't match the initial one.")
		}

		curve25519.ScalarBaseMult(&publicKey3, &privateKey)
		if !bytes.Equal(publicKey[:], publicKey3[:]) {
			t.Fatal("The public key doesn't match the value that curve25519 produced.")
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var publicKey, representative, privateKey [32]byte

	// Find the private key that results in a point that's in the image of the map.
	for {
		rand.Reader.Read(privateKey[:])
		if ScalarBaseMult(&publicKey, &representative, &privateKey) {
			break
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ScalarBaseMult(&publicKey, &representative, &privateKey)
	}
}

func BenchmarkMap(b *testing.B) {
	var publicKey, representative [32]byte
	rand.Reader.Read(representative[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RepresentativeToPublicKey(&publicKey, &representative)
	}
}

// copied test-vectors from:
// https://github.com/WhisperSystems/curve25519-java/blob/master/android/jni/ed25519/tests/tests.c
var sha512_correct_output = [64]byte{
	0x8E, 0x95, 0x9B, 0x75, 0xDA, 0xE3, 0x13, 0xDA,
	0x8C, 0xF4, 0xF7, 0x28, 0x14, 0xFC, 0x14, 0x3F,
	0x8F, 0x77, 0x79, 0xC6, 0xEB, 0x9F, 0x7F, 0xA1,
	0x72, 0x99, 0xAE, 0xAD, 0xB6, 0x88, 0x90, 0x18,
	0x50, 0x1D, 0x28, 0x9E, 0x49, 0x00, 0xF7, 0xE4,
	0x33, 0x1B, 0x99, 0xDE, 0xC4, 0xB5, 0x43, 0x3A,
	0xC7, 0xD3, 0x29, 0xEE, 0xB6, 0xDD, 0x26, 0x54,
	0x5E, 0x96, 0xE5, 0x5B, 0x87, 0x4B, 0xE9, 0x09,
}

var elligator_correct_output = [32]byte{
	0x5f, 0x35, 0x20, 0x00, 0x1c, 0x6c, 0x99, 0x36,
	0xa3, 0x12, 0x06, 0xaf, 0xe7, 0xc7, 0xac, 0x22,
	0x4e, 0x88, 0x61, 0x61, 0x9b, 0xf9, 0x88, 0x72,
	0x44, 0x49, 0x15, 0x89, 0x9d, 0x95, 0xf4, 0x6e,
}

var hashtopoint_correct_output1 = [32]byte{
	0xce, 0x89, 0x9f, 0xb2, 0x8f, 0xf7, 0x20, 0x91,
	0x5e, 0x14, 0xf5, 0xb7, 0x99, 0x08, 0xab, 0x17,
	0xaa, 0x2e, 0xe2, 0x45, 0xb4, 0xfc, 0x2b, 0xf6,
	0x06, 0x36, 0x29, 0x40, 0xed, 0x7d, 0xe7, 0xed,
}

var hashtopoint_correct_output2 = [32]byte{
	0xa0, 0x35, 0xbb, 0xa9, 0x4d, 0x30, 0x55, 0x33,
	0x0d, 0xce, 0xc2, 0x7f, 0x83, 0xde, 0x79, 0xd0,
	0x89, 0x67, 0x72, 0x4c, 0x07, 0x8d, 0x68, 0x9d,
	0x61, 0x52, 0x1d, 0xf9, 0x2c, 0x5c, 0xba, 0x77,
}

var calculatev_correct_output = [32]byte{
	0x1b, 0x77, 0xb5, 0xa0, 0x44, 0x84, 0x7e, 0xb9,
	0x23, 0xd7, 0x93, 0x18, 0xce, 0xc2, 0xc5, 0xe2,
	0x84, 0xd5, 0x79, 0x6f, 0x65, 0x63, 0x1b, 0x60,
	0x9b, 0xf1, 0xf8, 0xce, 0x88, 0x0b, 0x50, 0x9c,
}

func TestElligatorFast(t *testing.T) {
	// TODO remove sha512 tests:
	want := sha512_correct_output
	sha512Input := []byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
	got := sha512.Sum512(sha512Input)
	if !bytes.Equal(want[:], got[:]) {
		t.Fatal("SHA512 #1 isn't equal to test-vector")
	}
	sha512Input[111] ^= 1
	got = sha512.Sum512(sha512Input)
	if bytes.Equal(want[:], got[:]) {
		t.Fatal("SHA512 #2 shouldn't be the same")
	}

	var b [32]byte
	for count := 0; count < 32; count++ {
		b[count] = byte(count)
	}
	var in edwards25519.FieldElement
	var out edwards25519.FieldElement
	edwards25519.FeFromBytes(&in, &b)

	Elligator(&out, in)

	var b2 [32]byte
	edwards25519.FeToBytes(&b2, &out)
	//TEST("Elligator vector", memcmp(bytes, elligator_correct_output, 32) == 0);
	if !bytes.Equal(b2[:], elligator_correct_output[:]) {
		fmt.Println(hex.Dump(b2[:]))
		fmt.Println(hex.Dump(elligator_correct_output[:]))
		t.Fatal("Elligator test vector faile")
	}

	/* Elligator(0) == 0 test */
	edwards25519.FeZero(&in)
	Elligator(&out, in)

	var bi, bo [32]byte
	edwards25519.FeToBytes(&bi, &in)
	edwards25519.FeToBytes(&bo, &out)

	if !bytes.Equal(bi[:], bo[:]) {
		fmt.Println("Elligator(0) != 0")
	}

	/* ge_montx_to_p3(0) -> order2 point test */
	var one, negone, zero edwards25519.FieldElement
	edwards25519.FeOne(&one)
	edwards25519.FeZero(&zero)
	edwards25519.FeSub(&negone, &zero, &one)
	var p3 edwards25519.ExtendedGroupElement
	geMontXtoExtendedFieldElement(&p3, zero, 0)
	if !(edwards25519.FeIsequal(p3.X, zero) == 1 &&
		edwards25519.FeIsequal(p3.Y, negone) == 1 &&
		edwards25519.FeIsequal(p3.Z, one) == 1 &&
		edwards25519.FeIsequal(p3.T, zero) == 1) {
		t.Fatal("ge_montx_to_p3(0) isn't a order 2 point")
	}

	/* Hash to point vector test */
	var htp [32]byte
	for count := 0; count < 32; count++ {
		htp[count] = byte(count)
	}

	HashToPoint(&p3, htp[:])

	var htpb [32]byte
	p3.ToBytes(&htpb)
	if !bytes.Equal(htpb[:], hashtopoint_correct_output1[:]) {
		fmt.Println(hex.Dump(htpb[:]))
		fmt.Println(hex.Dump(hashtopoint_correct_output1[:]))
		t.Fatal("hash_to_point #1 failed")
	}

	for count := 0; count < 32; count++ {
		htp[count] = byte(count + 1)
	}

	HashToPoint(&p3, htp[:])
	p3.ToBytes(&htp)
	//TEST("hash_to_point #2", memcmp(htp, hashtopoint_correct_output2, 32) == 0);
	if !bytes.Equal(htpb[:], hashtopoint_correct_output2[:]) {
		fmt.Println(hex.Dump(htp[:]))
		fmt.Println(hex.Dump(hashtopoint_correct_output2[:]))
		t.Fatal("hash_to_point #2 failed")
	}
	// TODO add other tests from:
	// https://github.com/WhisperSystems/curve25519-java/blob/master/android/jni/ed25519/tests/tests.c
	/* calculate_U vector test */
}
