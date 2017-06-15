// This module implements a generic CONIKS auditor, i.e. the
// functionality that clients and auditors need to verify
// a server's STR history.

package auditor

import (
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	p "github.com/coniks-sys/coniks-go/protocol"
)

// Auditor verifies the hash chain of a specific directory.
type Auditor struct {
	signKey     sign.PublicKey
	verifiedSTR *p.DirSTR
	// trustedSTR is the old verified STR, which is the value
	// of verifiedSTR before it gets updated.
	trustedSTR *p.DirSTR
}

// New instantiates a new auditor state from a persistance storage.
func New(signKey sign.PublicKey, trusted *p.DirSTR) *Auditor {
	a := &Auditor{
		signKey:     signKey,
		verifiedSTR: trusted,
		trustedSTR:  trusted,
	}
	return a
}

// VerifiedSTR returns the newly verified STR.
func (a *Auditor) VerifiedSTR() *p.DirSTR {
	return a.verifiedSTR
}

// TrustedSTR returns the old verified STR, which is
// the value of VerifiedSTR() before it gets updated.
// This could be used in other operations such as
// promise verification.
func (a *Auditor) TrustedSTR() *p.DirSTR {
	return a.trustedSTR
}

// Update is supposed to be used
// by CONIKS clients to handle directory responses,
// and by CONIKS auditors to handle directory responses.
//
// It verifies the received range of STRs and updates
// the verified STR to the latest STR.
//
// Note that this function updates the `verifiedSTR`
// even the received STR is inconsistency.
func (a *Auditor) Update(msg *p.Response) error {
	if p.Errors[msg.Error] {
		return msg.Error
	}

	strs, ok := msg.DirectoryResponse.(*p.STRHistoryRange)
	if !ok || msg.Error != p.ReqSuccess || len(strs.STR) == 0 {
		return p.ErrMalformedDirectoryMessage
	}

	// FIXME: we are returning the error immediately
	// without saving the inconsistent STR
	// see: https://github.com/coniks-sys/coniks-go/pull/74#commitcomment-19804686
	switch {
	case strs.STR[0].Epoch == a.verifiedSTR.Epoch:
		if err := a.verifySTR(strs.STR[0]); err != nil {
			return err
		}
	case strs.STR[0].Epoch == a.verifiedSTR.Epoch+1:
		if err := a.verifySTRConsistency(a.verifiedSTR, strs.STR[0]); err != nil {
			return err
		}
	default:
		return p.CheckBadSTR
	}

	for i := 1; i < len(strs.STR); i++ {
		if err := a.verifySTRConsistency(strs.STR[i-1], strs.STR[i]); err != nil {
			return err
		}
	}
	a.verifiedSTR = strs.STR[len(strs.STR)-1]

	return nil
}

// Audit is supposed to be used
// by CONIKS clients to handle auditor responses,
// and by CONIKS auditors to handle directory responses.
// It is used to check for possible equivocation between
// the auditors' view and the client own view.
//
// TODO: if the auditor has returned a more recent STR,
// should the client update its savedSTR? Should this
// force a new round of monitoring?
func (a *Auditor) Audit(msg *p.Response) error {
	if p.Errors[msg.Error] {
		return msg.Error
	}

	strs, ok := msg.DirectoryResponse.(*p.STRHistoryRange)
	if !ok || msg.Error != p.ReqSuccess || len(strs.STR) != 1 {
		return p.ErrMalformedAuditorMessage
	}

	return a.verifySTR(strs.STR[0])
}

// verifySTR checks whether the received STR is the same with
// the saved STR in the audit state using reflect.DeepEqual().
// FIXME: check whether the STR was issued on time and whatnot.
// Maybe it has something to do w/ #81 and client transitioning between epochs.
// Try to verify w/ what's been saved
func (a *Auditor) verifySTR(str *p.DirSTR) error {
	if reflect.DeepEqual(a.verifiedSTR, str) {
		return nil
	}
	return p.CheckBadSTR
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the signing key signKey to verify the STR's signature.
// The signKey param either comes from a client's
// pinned signing key in its consistency state,
// or an auditor's pinned signing key in its history.
func (a *Auditor) verifySTRConsistency(savedSTR, str *p.DirSTR) error {
	// verify STR's signature
	if !a.signKey.Verify(str.Serialize(), str.Signature) {
		return p.CheckBadSignature
	}
	if str.VerifyHashChain(savedSTR) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return p.CheckBadSTR
}
