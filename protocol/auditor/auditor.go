// This module implements a generic CONIKS auditor, i.e. the
// functionality that clients and auditors need to verify
// a server's STR history.

package auditor

import (
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
)

// Auditor provides a generic interface allowing different
// auditor types to implement specific auditing functionality.
type Auditor interface {
	AuditDirectory([]*protocol.DirSTR) error
}

// AudState verifies the hash chain of a specific directory.
type AudState struct {
	signKey     sign.PublicKey
	verifiedSTR *protocol.DirSTR
}

var _ Auditor = (*AudState)(nil)

// New instantiates a new auditor state from a persistance storage.
func New(signKey sign.PublicKey, verified *protocol.DirSTR) *AudState {
	a := &AudState{
		signKey:     signKey,
		verifiedSTR: verified,
	}
	return a
}

// Verify verifies a signature sig on message using the underlying
// public-key of the AudState.
func (a *AudState) Verify(message, sig []byte) bool {
	return a.signKey.Verify(message, sig)
}

// VerifiedSTR returns the newly verified STR.
func (a *AudState) VerifiedSTR() *protocol.DirSTR {
	return a.verifiedSTR
}

// Update updates the auditor's verifiedSTR to newSTR
func (a *AudState) Update(newSTR *protocol.DirSTR) {
	a.verifiedSTR = newSTR
}

// compareWithVerified checks whether the received STR is the same as
// the verified STR in the AudState using reflect.DeepEqual().
func (a *AudState) compareWithVerified(str *protocol.DirSTR) error {
	if reflect.DeepEqual(a.verifiedSTR, str) {
		return nil
	}
	return protocol.CheckBadSTR
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the signing key signKey to verify the STR's signature.
// The signKey param either comes from a client's
// pinned signing key in its consistency state,
// or an auditor's pinned signing key in its history.
func (a *AudState) verifySTRConsistency(prevSTR, str *protocol.DirSTR) error {
	// verify STR's signature
	if !a.signKey.Verify(str.Serialize(), str.Signature) {
		return protocol.CheckBadSignature
	}
	if str.VerifyHashChain(prevSTR) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return protocol.CheckBadSTR
}

// CheckSTRAgainstVerified checks an STR str against the a.verifiedSTR.
// If str's Epoch is the same as the verified, CheckSTRAgainstVerified()
// compares the two STRs directly. If str is one epoch ahead of the
// a.verifiedSTR, CheckSTRAgainstVerified() checks the consistency between
// the two STRs.
// CheckSTRAgainstVerified() returns nil if the check passes,
// or the appropriate consistency check error if any of the checks fail,
// or str's epoch is anything other than the same or one ahead of
// a.verifiedSTR.
func (a *AudState) CheckSTRAgainstVerified(str *protocol.DirSTR) error {
	// FIXME: check whether the STR was issued on time and whatnot.
	// Maybe it has something to do w/ #81 and client
	// transitioning between epochs.
	// Try to verify w/ what's been saved
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
		return protocol.CheckBadSTR
	}

	return nil
}

// VerifySTRRange checks the consistency of a range
// of a directory's STRs. It begins by verifying the STR consistency between
// the given prevSTR and the first STR in the given range, and
// then verifies the consistency between each subsequent STR pair.
func (a *AudState) VerifySTRRange(prevSTR *protocol.DirSTR, strs []*protocol.DirSTR) error {
	prev := prevSTR
	for i := 0; i < len(strs); i++ {
		str := strs[i]
		if str == nil {
			return protocol.ErrMalformedMessage
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
func (a *AudState) AuditDirectory(strs []*protocol.DirSTR) error {
	// validate strs
	if len(strs) == 0 {
		return protocol.ErrMalformedMessage
	}

	// check STR against the latest verified STR
	if err := a.CheckSTRAgainstVerified(strs[0]); err != nil {
		return err
	}

	// verify the entire range if we have received more than one STR
	if len(strs) > 1 {
		if err := a.VerifySTRRange(strs[0], strs[1:]); err != nil {
			return err
		}
	}

	return nil
}
