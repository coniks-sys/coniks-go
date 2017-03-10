// Implements all consistency check operations done by a CONIKS client
// on data received from a CONIKS directory.
// These include data binding proof verification,
// and non-equivocation checks.
// TODO: move all STR-verifying functionality to a separate module

package protocol

import (
	"bytes"
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

// ConsistencyChecks stores the latest consistency check
// state of a CONIKS client. This includes the latest SignedTreeRoot,
// all the verified name-to-key bindings of the client,
// as well as a directory's policies (e.g., whether the
// TemporaryBinding extension is being used).
//
// The client should create a new ConsistencyChecks instance only once,
// when it registers its user's binding with a ConiksDirectory.
// This ConsistencyChecks instance will then be used to verify
// subsequent responses from the ConiksDirectory to any
// client request.
type ConsistencyChecks struct {
	// auditState stores the latest verified signed tree root
	// as well as the server's signing key
	auditState *auditorState
	Bindings map[string][]byte

	// extensions settings
	useTBs bool
	TBs    map[string]*TemporaryBinding
}

// NewCC creates an instance of ConsistencyChecks using
// a CONIKS directory's pinned STR at epoch 0, or
// the consistency state read from persistent storage.
func NewCC(savedSTR *m.SignedTreeRoot, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {
	// TODO: see #110
	if !useTBs {
		panic("[coniks] Currently the server is forced to use TBs")
	}
	cc := &ConsistencyChecks{
		auditState: newAuditorState(signKey, savedSTR),
		Bindings: make(map[string][]byte),
		useTBs:   useTBs,
	}
	if useTBs {
		cc.TBs = make(map[string]*TemporaryBinding)
	}
	return cc
}

// HandleResponse verifies the directory's response for a request.
// It first verifies the directory's returned status code of the request.
// If the status code is not in the Errors array, it means
// the directory has successfully handled the request.
// The verifier will then check the consistency (i.e. binding validity
// and non-equivocation) of the response.
//
// HandleResponse() will panic if it is called with an int
// that isn't a valid/known request type.
//
// Note that the consistency state will be updated regardless of
// whether the checks pass / fail, since a response message contains
// cryptographic proof of having been issued nonetheless.
func (cc *ConsistencyChecks) HandleResponse(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	if err := msg.validate(); err != nil {
		return err.(ErrorCode)
	}
	switch requestType {
	case RegistrationType, KeyLookupType:
		if _, ok := msg.DirectoryResponse.(*DirectoryProof); !ok {
			return ErrMalformedDirectoryMessage
		}
	case MonitoringType, KeyLookupInEpochType:
		if _, ok := msg.DirectoryResponse.(*DirectoryProofs); !ok {
			return ErrMalformedDirectoryMessage
		}
	default:
		panic("[coniks] Unknown request type")
	}
	if err := cc.updateSTR(requestType, msg); err != nil {
		return err.(ErrorCode)
	}
	if err := cc.checkConsistency(requestType, msg, uname, key); err != CheckPassed {
		return err
	}
	if err := cc.updateTBs(requestType, msg, uname, key); err != nil {
		return err.(ErrorCode)
	}
	recvKey, _ := msg.GetKey()
	cc.Bindings[uname] = recvKey
	return CheckPassed
}

func (cc *ConsistencyChecks) updateSTR(requestType int, msg *Response) error {
	var str *m.SignedTreeRoot
	switch requestType {
	case RegistrationType, KeyLookupType:
		str = msg.DirectoryResponse.(*DirectoryProof).STR
		// First response
		if cc.auditState.latestSTR == nil {
			cc.auditState.latestSTR = str
			return nil
		}
		if err := cc.auditState.verfySTR(str); err == nil {
			return nil
		}
		// Otherwise, expect that we've entered a new epoch
		if err := cc.auditState.verifySTRConsistency(str); err != nil {
			return err
		}

	default:
		panic("[coniks] Unknown request type")
	}

	// And update the saved STR
	cc.auditState.latestSTR = str
	return nil
}

func (cc *ConsistencyChecks) checkConsistency(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	var err error
	switch requestType {
	case RegistrationType:
		err = cc.verifyRegistration(msg, uname, key)
	case KeyLookupType:
		err = cc.verifyKeyLookup(msg, uname, key)
	default:
		panic("[coniks] Unknown request type")
	}
	return err.(ErrorCode)
}

func (cc *ConsistencyChecks) verifyRegistration(msg *Response,
	uname string, key []byte) error {
	df := msg.DirectoryResponse.(*DirectoryProof)
	ap := df.AP
	str := df.STR

	proofType := ap.ProofType()
	switch {
	case msg.Error == ReqNameExisted && proofType == m.ProofOfInclusion:
	case msg.Error == ReqNameExisted && proofType == m.ProofOfAbsence && cc.useTBs:
	case msg.Error == ReqSuccess && proofType == m.ProofOfAbsence:
	default:
		return ErrMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	return CheckPassed
}

func (cc *ConsistencyChecks) verifyKeyLookup(msg *Response,
	uname string, key []byte) error {
	df := msg.DirectoryResponse.(*DirectoryProof)
	ap := df.AP
	str := df.STR

	proofType := ap.ProofType()
	switch {
	case msg.Error == ReqNameNotFound && proofType == m.ProofOfAbsence:
	// FIXME: This would be changed when we support key changes
	case msg.Error == ReqSuccess && proofType == m.ProofOfInclusion:
	case msg.Error == ReqSuccess && proofType == m.ProofOfAbsence && cc.useTBs:
	default:
		return ErrMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	return CheckPassed
}

func verifyAuthPath(uname string, key []byte,
	ap *m.AuthenticationPath,
	str *m.SignedTreeRoot) error {

	// verify VRF Index
	vrfKey := GetPolicies(str).VrfPublicKey
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return CheckBadVRFProof
	}

	if key == nil {
		// key is nil when the user does lookup for the first time.
		// Accept the received key as TOFU
		key = ap.Leaf.Value
	}

	switch err := ap.Verify([]byte(uname), key, str.TreeHash); err {
	case m.ErrBindingsDiffer:
		return CheckBindingsDiffer
	case m.ErrUnverifiableCommitment:
		return CheckBadCommitment
	case m.ErrIndicesMismatch:
		return CheckBadLookupIndex
	case m.ErrUnequalTreeHashes:
		return CheckBadAuthPath
	case nil:
		return nil
	default:
		panic("[coniks] Unknown error: " + err.Error())
	}
}

func (cc *ConsistencyChecks) updateTBs(requestType int, msg *Response,
	uname string, key []byte) error {
	if !cc.useTBs {
		return nil
	}
	switch requestType {
	case RegistrationType:
		df := msg.DirectoryResponse.(*DirectoryProof)
		if df.AP.ProofType() == m.ProofOfAbsence {
			if err := cc.verifyReturnedPromise(df, key); err != nil {
				return err
			}
			cc.TBs[uname] = df.TB
		}
		return nil

	case KeyLookupType:
		df := msg.DirectoryResponse.(*DirectoryProof)
		ap := df.AP
		str := df.STR
		proofType := ap.ProofType()
		switch {
		case msg.Error == ReqSuccess && proofType == m.ProofOfInclusion:
			if err := cc.verifyFulfilledPromise(uname, str, ap); err != nil {
				return err
			}
			delete(cc.TBs, uname)

		case msg.Error == ReqSuccess && proofType == m.ProofOfAbsence:
			if err := cc.verifyReturnedPromise(df, key); err != nil {
				return err
			}
			cc.TBs[uname] = df.TB
		}

	default:
		panic("[coniks] Unknown request type")
	}
	return nil
}

// verifyFulfilledPromise verifies issued TBs were inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	// FIXME: Which epoch did this lookup happen in?
	if tb, ok := cc.TBs[uname]; ok {
		if !bytes.Equal(ap.LookupIndex, tb.Index) ||
			!bytes.Equal(ap.Leaf.Value, tb.Value) {
			return CheckBrokenPromise
		}
	}
	return nil
}

// verifyReturnedPromise validates a returned promise.
// Note that the directory returns a promise iff the returned proof is
// _a proof of absence_.
// 	If the request is a registration, and
// 	- the request is successful, then the directory should return a promise for the new binding.
// 	- the request is failed because of ReqNameExisted, then the directory should return a promise for that existed binding.
//
// 	If the request is a key lookup, and
// 	- the request is successful, then the directory should return a promise for the lookup binding.
// These above checks should be performed before calling this method.
func (cc *ConsistencyChecks) verifyReturnedPromise(df *DirectoryProof,
	key []byte) error {
	ap := df.AP
	str := df.STR
	tb := df.TB

	if tb == nil {
		return CheckBadPromise
	}

	// verify TB's Signature
	if !cc.auditState.signKey.Verify(tb.Serialize(str.Signature), tb.Signature) {
		return CheckBadSignature
	}

	if !bytes.Equal(tb.Index, ap.LookupIndex) {
		return CheckBadPromise
	}

	// key could be nil if we have no information about
	// the existed binding (TOFU).
	if key != nil && !bytes.Equal(tb.Value, key) {
		return CheckBindingsDiffer
	}
	return nil
}
