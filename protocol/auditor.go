// This module implements a generic CONIKS auditor, i.e. the
// functionality that clients and auditors need to verify
// a server's STR history.

package protocol

import (
	"fmt"
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

// Auditor provides a generic interface allowing different
// auditor types to implement specific auditing functionality.
type Auditor interface {
	AuditDirectory([]*DirSTR) error
}

// AudState verifies the hash chain of a specific directory.
type AudState struct {
	signKey     sign.PublicKey
	verifiedSTR *DirSTR
}

var _ Auditor = (*AudState)(nil)

// NewAuditor instantiates a new auditor state from a persistance storage.
func NewAuditor(signKey sign.PublicKey, verified *DirSTR) *AudState {
	a := &AudState{
		signKey:     signKey,
		verifiedSTR: verified,
	}
	return a
}

// VerifiedSTR returns the newly verified STR.
func (a *AudState) VerifiedSTR() *DirSTR {
	return a.verifiedSTR
}

// Update updates the auditor's verifiedSTR to newSTR
func (a *AudState) Update(newSTR *DirSTR) {
	a.verifiedSTR = newSTR
}

// compareWithVerified checks whether the received STR is the same as
// the verified STR in the AudState using reflect.DeepEqual().
func (a *AudState) compareWithVerified(str *DirSTR) error {
	if reflect.DeepEqual(a.verifiedSTR, str) {
		return nil
	}
	return CheckBadSTR
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the signing key signKey to verify the STR's signature.
// The signKey param either comes from a client's
// pinned signing key in its consistency state,
// or an auditor's pinned signing key in its history.
func (a *AudState) verifySTRConsistency(prevSTR, str *DirSTR) error {
	// verify STR's signature
	if !a.signKey.Verify(str.Serialize(), str.Signature) {
		return CheckBadSignature
	}
	if str.VerifyHashChain(prevSTR) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return CheckBadSTR
}

// checkSTRAgainstVerified checks an STR str against the a.verifiedSTR.
// If str's Epoch is the same as the verified, checkSTRAgainstVerified()
// compares the two STRs directly. If str is one epoch ahead of the
// a.verifiedSTR, checkSTRAgainstVerified() checks the consistency between
// the two STRs.
// checkSTRAgainstVerified() returns nil if the check passes,
// or the appropriate consistency check error if any of the checks fail,
// or str's epoch is anything other than the same or one ahead of
// a.verifiedSTR.
func (a *AudState) checkSTRAgainstVerified(str *DirSTR) error {
	// FIXME: check whether the STR was issued on time and whatnot.
	// Maybe it has something to do w/ #81 and client
	// transitioning between epochs.
	// Try to verify w/ what's been saved

	// FIXME: we are returning the error immediately
	// without saving the inconsistent STR
	// see: https://github.com/coniks-sys/coniks-go/pull/74#commitcomment-19804686
	switch {
	case str.Epoch == a.verifiedSTR.Epoch:
		// Checking an STR in the same epoch
		if err := a.compareWithVerified(str); err != nil {
			return err
		}
	case str.Epoch == a.verifiedSTR.Epoch+1:
		// Otherwise, expect that we've entered a new epoch
		if err := a.verifySTRConsistency(a.verifiedSTR, str); err != nil {
			return err
		}
	default:
		return CheckBadSTR
	}

	return nil
}

// verifySTRRange checks the consistency of a range
// of a directory's STRs. It begins by verifying the STR consistency between
// the given prevSTR and the first STR in the given range, and
// then verifies the consistency between each subsequent STR pair.
func (a *AudState) verifySTRRange(prevSTR *DirSTR, strs []*DirSTR) error {
	prev := prevSTR
	for i := 0; i < len(strs); i++ {
		str := strs[i]
		if str == nil {
			// FIXME: if this comes from the auditor, this
			// should really be an ErrMalformedAuditorMessage
			return ErrMalformedDirectoryMessage
		}

		// verify the consistency of each STR in the range
		if err := a.verifySTRConsistency(prev, str); err != nil {
			return err
		}

		prev = str
	}

	return nil
}

// AuditDirectory validates a range of STRs received from a CONIKS directory.
// AuditDirectory() checks the consistency of the oldest STR in the range
// against the verifiedSTR, and verifies the remaining
// range if the message contains more than one STR.
// AuditDirectory() returns the appropriate consistency check error
// if any of the checks fail, or nil if the checks pass.
func (a *AudState) AuditDirectory(strs []*DirSTR) error {

	// validate strs
	if strs == nil {
		return ErrMalformedDirectoryMessage
	}

	// check STR against the latest verified STR
	if err := a.checkSTRAgainstVerified(strs[0]); err != nil {
		return err
	}

	// verify the entire range if we have received more than one STR
	if len(strs) > 1 {
		if err := a.verifySTRRange(strs[0], strs[1:]); err != nil {
			return err
		}
	}

	return nil
}

// ComputeDirectoryIdentity returns the hash of
// the directory's initial STR as a byte array.
// It panics if the STR isn't an initial STR (i.e. str.Epoch != 0).
func ComputeDirectoryIdentity(str *DirSTR) [crypto.HashSizeByte]byte {
	if str.Epoch != 0 {
		panic(fmt.Sprintf("[coniks] Expect epoch 0, got %x", str.Epoch))
	}

	var initSTRHash [crypto.HashSizeByte]byte
	copy(initSTRHash[:], crypto.Digest(str.Signature))
	return initSTRHash
}
