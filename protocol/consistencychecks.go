// Implements all consistency check operations done by a CONIKS client
// on data received from a CONIKS directory.
// These include data binding proof verification,
// and non-equivocation checks.

package protocol

import (
	"bytes"
	"reflect"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

// ConsistencyChecks stores the latest consistency check
// state of a CONIKS client. This includes the latest epoch
// and SignedTreeRoot value, as well as directory's policies
// (e.g., whether the TemporaryBinding extension is being used or not)
// The client should create a new ConsistencyChecks instance only once,
// when she registers her binding with a ConiksDirectory.
// This ConsistencyChecks instance then will be used to verify
// the returned responses from the ConiksDirectory.
type ConsistencyChecks struct {
	SavedSTR *m.SignedTreeRoot

	// extensions settings
	useTBs bool
	TBs    map[string]*TemporaryBinding

	// signing key
	signKey sign.PublicKey
}

// NewCC creates an instance of ConsistencyChecks using
// the pinned directory's STR at epoch 0 or
// the consistency state read from a persistent storage.
func NewCC(savedSTR *m.SignedTreeRoot, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {
	// TODO: see #110
	if !useTBs {
		panic("[coniks] Currently the server is forced to use TBs.")
	}
	cc := &ConsistencyChecks{
		SavedSTR: savedSTR,
		useTBs:   useTBs,
		signKey:  signKey,
	}
	if useTBs {
		cc.TBs = make(map[string]*TemporaryBinding)
	}
	return cc
}

// HandleResponse verifies the directory's response for a request.
// It first verifies the directory's returned status code of the request.
// If the status code is not in the ErrorResponses array, it means
// the directory has successfully handled the request.
// The verifier will then verify the consistency state of the response.
// This will panic if it is called with an int
// which isn't a valid/known request-type.
// Note that the consistency state would be updated regardless of
// whether the checks pass / fail, since it contains proof of being issued.
func (cc *ConsistencyChecks) HandleResponse(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	if ErrorResponses[msg.Error] {
		return msg.Error
	}
	switch requestType {
	case RegistrationType, KeyLookupType:
		if _, ok := msg.DirectoryResponse.(*DirectoryProof); !ok {
			return ErrorMalformedDirectoryMessage
		}
	default:
		panic("[coniks] Unknown request type.")
	}
	if err := cc.updateSTR(requestType, msg); err != nil {
		return err.(ErrorCode)
	}
	if err := cc.checkConsistency(requestType, msg, uname, key); err != Passed {
		return err
	}
	if err := cc.updateTBs(requestType, msg, uname, key); err != nil {
		return err.(ErrorCode)
	}
	return Passed
}

func (cc *ConsistencyChecks) updateSTR(requestType int, msg *Response) error {
	var str *m.SignedTreeRoot
	switch requestType {
	case RegistrationType, KeyLookupType:
		str = msg.DirectoryResponse.(*DirectoryProof).STR
		// First response
		if cc.SavedSTR == nil {
			cc.SavedSTR = str
			return nil
		}
		// FIXME: check whether the STR was issued on time and whatnot.
		// Maybe it has something to do w/ #81 and client transitioning between epochs.
		// Try to verify w/ what's been saved
		if err := cc.verifySTR(str); err == nil {
			return nil
		}
		// Otherwise, expect that we've entered a new epoch
		if err := cc.verifySTRConsistency(cc.SavedSTR, str); err != nil {
			return err
		}
	}

	// And update the saved STR
	cc.SavedSTR = str
	return nil
}

// verifySTR checks whether the received STR is the same with
// the SavedSTR using reflect.DeepEqual().
func (cc *ConsistencyChecks) verifySTR(str *m.SignedTreeRoot) error {
	if reflect.DeepEqual(cc.SavedSTR, str) {
		return nil
	}
	return ErrorBadSTR
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// It uses the pinned signing key in cc
// to verify the STR's signature and should not verify
// the hash chain using the STR stored in cc.
func (cc *ConsistencyChecks) verifySTRConsistency(savedSTR, str *m.SignedTreeRoot) error {
	// verify STR's signature
	if !cc.signKey.Verify(str.Serialize(), str.Signature) {
		return ErrorBadSignature
	}
	if str.VerifyHashChain(savedSTR) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return ErrorBadSTR
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
		panic("[coniks] Unknown request type.")
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
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfInclusion:
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfAbsence && cc.useTBs:
	case msg.Error == Success && proofType == m.ProofOfAbsence:
	default:
		return ErrorMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	return Passed
}

func (cc *ConsistencyChecks) verifyKeyLookup(msg *Response,
	uname string, key []byte) error {
	df := msg.DirectoryResponse.(*DirectoryProof)
	ap := df.AP
	str := df.STR

	proofType := ap.ProofType()
	switch {
	case msg.Error == ErrorNameNotFound && proofType == m.ProofOfAbsence:
	// FIXME: This would be changed when we support key changes
	case msg.Error == Success && proofType == m.ProofOfInclusion:
	case msg.Error == Success && proofType == m.ProofOfAbsence && cc.useTBs:
	default:
		return ErrorMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	return Passed
}

func verifyAuthPath(uname string, key []byte,
	ap *m.AuthenticationPath,
	str *m.SignedTreeRoot) error {

	// verify VRF Index
	vrfKey := vrf.PublicKey(str.Policies.VrfPublicKey)
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return ErrorBadVRFProof
	}

	if key == nil {
		// key is nil when the user does lookup for the first time.
		// Accept the received key as TOFU
		key = ap.Leaf.Value
	}

	// verify auth path
	if !ap.Verify([]byte(uname), key, str.TreeHash) {
		return ErrorBadAuthPath
	}

	return nil
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
		case msg.Error == Success && proofType == m.ProofOfInclusion:
			if err := cc.verifyFulfilledPromise(uname, str, ap); err != nil {
				return err
			}

		case msg.Error == Success && proofType == m.ProofOfAbsence:
			if err := cc.verifyReturnedPromise(df, key); err != nil {
				return err
			}
			cc.TBs[uname] = df.TB
		}
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
			return ErrorBrokenPromise
		}
		delete(cc.TBs, uname)
	}
	return nil
}

// verifyReturnedPromise validates a returned promise.
// Note that the directory returns a promise iff the returned proof is
// _a proof of absence_.
// 	If the request is a registration, and
// 	- the request is successful, then the directory should return a promise for the new binding.
// 	- the request is failed because of ErrorNameExisted, then the directory should return a promise for that existed binding.
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
		return ErrorBadPromise
	}

	// verify TB's Signature
	if !cc.signKey.Verify(tb.Serialize(str.Signature), tb.Signature) {
		return ErrorBadSignature
	}

	if tb.Verify(ap.LookupIndex, key) {
		return nil
	}
	return ErrorBadPromise
}
