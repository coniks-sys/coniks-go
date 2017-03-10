// This module implements a generic CONIKS auditor, i.e. the
// functionality that clients and auditors need to verify
// a server's STR history.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

type auditorState struct {
	signKey   sign.PublicKey
	latestSTR *m.SignedTreeRoot
}

func newAuditorState(signKey sign.PublicKey, latest *m.SignedTreeRoot) *auditorState {
	a := &auditorState{
		signKey: signKey,
		latestSTR: latest,
	}
	return a
}

// handleDirectorySTRs is supposed to be used by CONIKS clients to
// handle auditor responses, and by CONIKS auditors to handle directory
// responses.
func (a *auditorState) HandleDirectorySTRs(requestType int, msg *Response,
	e error, isClient bool) error {
	if err := msg.validate(); err != nil {
		return e
	}

	switch requestType {
	case AuditType:
		if _, ok := msg.DirectoryResponse.(*ObservedSTR); !ok {
			return e
		}
	case AuditInEpochType:
		// this is the default request type for an auditor
		// since the auditor conservatively assumes it may
		// have missed epochs

		if _, ok := msg.DirectoryResponse.(*ObservedSTRs); !ok {
			return e
		}
	default:
		panic("[coniks] Unknown auditing request type")
	}

	// clients only care about comparing the STR with the savedSTR
	// TODO: if the auditor has returned a more recent STR,
	// should the client update its savedSTR? Should this
	// force a new round of monitoring?
	if isClient {
		a.compareSavedSTR(requestType, msg)
	}

	// we assume the requestType is AuditInEpochType if we're here

	// verify the timeliness of the STR if we're the auditor
	// check the consistency of the newly received STRs
	if err := a.verifySTRConsistencyRange(strs); err != nil {
		return err
	}

	return nil
}

// verifySTR checks whether the received STR is the same with
// the saved STR in the audit state using reflect.DeepEqual().
// FIXME: check whether the STR was issued on time and whatnot.
// Maybe it has something to do w/ #81 and client transitioning between epochs.
// Try to verify w/ what's been saved
func (a *auditorState) verifySTR(str *m.SignedTreeRoot) error {
	return a.compareSavedSTR(str)
}

func (a *auditorState) compareSavedSTR(str *m.SignedTreeRoot) error {
	if reflect.DeepEqual(a.latestSTR, str) {
		return nil
	}
	return CheckBadSTR
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the signing key signKey to verify the STR's signature.
// The signKey param either comes from a client's
// pinned signing key in cc, or an auditor's pinned signing key
// in its history.
// In the case of a client-side consistency check, verifySTRConsistency()
// should not verify the hash chain using the STR stored in cc.
func (a *auditorState) verifySTRConsistency(str *m.SignedTreeRoot) error {
	// verify STR's signature
	if !a.signKey.Verify(str.Serialize(), str.Signature) {
		return CheckBadSignature
	}
	if str.VerifyHashChain(a.latestSTR) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return CheckBadSTR
}

func (a *auditorState) verifySTRConsistencyRange(strs []*m.SignedTreeRoot) error {
	// FIXME: implement me
}
