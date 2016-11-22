// Package crypto contains the cryptographic routines for CONIKS:
// hashing, cryptographic commitments, digital signatures, VRF,
// and random number generation.
//
// These cryptographic routines are used to:
//
// - hash arbitrary data (`Digest`) using SHA3 (SHAKE128),
//
// - create a cryptographic commit to arbitrary data,
//
// - generate a random slice of bytes,
//
// - sign data and verify signatures using Ed25519,
//
// - apply a VRF to data and verify the VRF proof.
package crypto
