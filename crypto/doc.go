// Package crypto contains some cryptographic routines, to:
// - hash arbitrary data (`Digest`) using sha3 (shake128)
// - create a cryptographic commit to arbitrary data
// - generate a random slice of bytes
// - sign data and verify signatures using ed25519
// - apply a VRF to data and verify the VRF proof.
package crypto
