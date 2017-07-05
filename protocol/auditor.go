// This module implements a generic CONIKS auditor, i.e. the
// functionality that clients and auditors need to verify
// a server's STR history.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type auditorState struct {
	signKey   sign.PublicKey
	latestSTR *DirSTR
}

func newAuditorState(signKey sign.PublicKey, initSTR *DirSTR) *auditorState {
	a := new (auditorState)
	a.signKey = signKey
	a.latestSTR = initSTR
	return a
}

type auditor interface {
	updateLatestSTR(*DirSTR)
	HandleSTRResponse(int, *Response, string) ErrorCode
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the signing key signKey to verify the STR's signature.
// The signKey param either comes from a client's
// pinned signing key in cc, or an auditor's pinned signing key
// in its history.
// In the case of a client-side consistency check, verifySTRConsistency()
// should not verify the hash chain using the STR stored in cc.
func (a *auditorState) verifySTRConsistency(prevSTR, str *DirSTR) error {
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

func (a *auditorState) verifySTRConsistencyRange(strs []*DirSTR) error {

	prev := a.latestSTR
	for i := 0; i < len(strs); i++ {
		str := strs[i]

		// verify the consistency of each STR in the range
		err := a.verifySTRConsistency(prev, str)

		if err != nil {
			return err
		}

		prev = str
	}

	return nil
}
