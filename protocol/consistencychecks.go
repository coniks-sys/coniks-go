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
// the pinning directory's STR at epoch 0 or
// the consistency state read from a persistent storage.
func NewCC(savedSTR *m.SignedTreeRoot, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {
	// TODO: see #110
	if !useTBs {
		panic("[coniks] Currently the server is forced to use TBs.")
	}
	if savedSTR == nil {
		panic("[coniks] Expect a non-nil consistency state.")
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

func (cc *ConsistencyChecks) HandleResponse(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	if ErrorResponses[msg.Error] {
		return msg.Error
	}
	if err := cc.updateSTR(requestType, msg); err != nil {
		return err.(ErrorCode)
	}
	if err := cc.checkConsistency(requestType, msg, uname, key); err != Passed {
		return err
	}
	if cc.useTBs {
		if err := cc.updateTBs(requestType, msg, uname); err != nil {
			return err.(ErrorCode)
		}
	}
	return Passed
}

func (cc *ConsistencyChecks) updateSTR(requestType int, msg *Response) error {
	var str *m.SignedTreeRoot
	switch requestType {
	case RegistrationType, KeyLookupType:
		df, ok := msg.DirectoryResponse.(*DirectoryProof)
		if !ok {
			return ErrorMalformedDirectoryMessage
		}
		str = df.STR
	default:
		panic("[coniks] Unknown request type.")
	}
	// Try to verify w/ what's been saved
	if err := cc.verifySTR(str); err == nil {
		return nil
	}
	// Otherwise, expect that we've enterred a new epoch
	if err := cc.verifySTRConsistency(cc.SavedSTR, str); err != nil {
		return err
	}
	// And update the saved STR
	cc.SavedSTR = str
	return nil
}

func (cc *ConsistencyChecks) updateTBs(requestType int, msg *Response,
	uname string) error {
	var df *DirectoryProof
	switch requestType {
	case RegistrationType, KeyLookupType:
		var ok bool
		if df, ok = msg.DirectoryResponse.(*DirectoryProof); !ok {
			return ErrorMalformedDirectoryMessage
		}
	default:
		panic("[coniks] Unknown request type.")
	}
	switch requestType {
	case RegistrationType:
		if msg.Error == Success {
			cc.TBs[uname] = df.TB
		}
		return nil
	case KeyLookupType:
		ap := df.AP
		proofType := ap.ProofType()
		// FIXME: Which epoch did this lookup happen in?
		switch {
		case msg.Error == Success && proofType == m.ProofOfInclusion:
			if tb, ok := cc.TBs[uname]; ok {
				if !bytes.Equal(ap.LookupIndex, tb.Index) ||
					!bytes.Equal(ap.Leaf.Value, tb.Value) {
					return ErrorBrokenPromise
				}
				delete(cc.TBs, uname)
			}
		case msg.Error == Success && proofType == m.ProofOfAbsence:
			cc.TBs[uname] = df.TB
		}
	}
	return nil
}

func (cc *ConsistencyChecks) checkConsistency(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	var err error
	switch requestType {
	case RegistrationType:
		err = cc.verifyRegistration(requestType, msg, uname, key)
	case KeyLookupType:
		err = cc.verifyKeyLookup(requestType, msg, uname, key)
	case MonitoringType:
	case KeyLookupInEpochType:
	default:
		panic("[coniks] Unknown request type.")
	}
	return err.(ErrorCode)
}

func (cc *ConsistencyChecks) verifyRegistration(requestType int,
	msg *Response, uname string, key []byte) error {
	df, ok := msg.DirectoryResponse.(*DirectoryProof)
	if !ok {
		return ErrorMalformedDirectoryMessage
	}

	ap := df.AP
	str := df.STR

	if err := cc.verifySTR(str); err != nil {
		return err
	}

	proofType := ap.ProofType()
	switch {
	case msg.Error == Success && proofType == m.ProofOfAbsence:
		if cc.useTBs {
			if err := cc.verifyReturnedPromise(df, uname, key); err != nil {
				return err
			}
		}
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfInclusion:
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfAbsence && cc.useTBs:
		if err := cc.verifyReturnedPromise(df, uname, key); err != nil {
			return err
		}
	default:
		return ErrorMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	return Passed
}

func (cc *ConsistencyChecks) verifyKeyLookup(requestType int,
	msg *Response, uname string, key []byte) error {
	df, ok := msg.DirectoryResponse.(*DirectoryProof)
	if !ok {
		return ErrorMalformedDirectoryMessage
	}

	ap := df.AP
	str := df.STR

	if err := cc.verifySTR(str); err != nil {
		return err
	}

	proofType := ap.ProofType()
	switch {
	case msg.Error == ErrorNameNotFound && proofType == m.ProofOfAbsence:
		// FIXME: Do we have a TB for this name?
	case msg.Error == Success && proofType == m.ProofOfInclusion:
	case msg.Error == Success && proofType == m.ProofOfAbsence && cc.useTBs:
		if err := cc.verifyReturnedPromise(df, uname, key); err != nil {
			return err
		}
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
		// key is nil when the user does lookup for the first time
		key = ap.Leaf.Value
	}

	// verify auth path
	if !ap.Verify([]byte(uname), key, str.TreeHash) {
		return ErrorBadAuthPath
	}

	return nil
}

// verifySTRConsistency checks the consistency between 2 snapshots.
// This should be called if the request is either registration or
// monitoring. It uses the pinning signing key in cc
// to verify the STR's signature and should not verify
// the hash chain using the STR stored in cc.
func (cc *ConsistencyChecks) verifySTRConsistency(savedSTR, str *m.SignedTreeRoot) error {
	// verify STR's signature
	if !cc.signKey.Verify(str.Serialize(), str.Signature) {
		return ErrorBadSignature
	}

	// TODO: clearly verify which is the client's actual expectation. See #81
	if str.Epoch == savedSTR.Epoch+1 && str.VerifyHashChain(savedSTR.Signature) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return ErrorBadSTR
}

// verifySTR checks whether the received STR is the same with
// the SavedSTR using reflect.DeepEqual().
// This should be called if the request is lookup, since the SavedSTR
// should only be updated in the beginning of each epoch by registration
// or monitoring requests.
func (cc *ConsistencyChecks) verifySTR(str *m.SignedTreeRoot) error {
	if reflect.DeepEqual(cc.SavedSTR, str) {
		return nil
	}
	return ErrorBadSTR
}

// verifyReturnedPromise validates the returned promise
// based on the request type. Note that the directory
// returns a promise iff the returned proof is
// _a proof of absence_.
// 	If the request is a registration, and
// 	- the request is successful, then the directory should return a promise for the new binding.
// 	- the request is failed because of ErrorNameExisted, then the directory should return a promise for that existed binding.
//
// 	If the request is a key lookup, and
// 	- the request is successful, then the directory should return a promise for the lookup binding.
// These above checks should be performed before calling this method.
func (cc *ConsistencyChecks) verifyReturnedPromise(df *DirectoryProof,
	uname string, key []byte) error {
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

	// verify TB's VRF index
	if !bytes.Equal(tb.Index, ap.LookupIndex) {
		return ErrorBadIndex
	}

	// verify TB's value
	// key could be nil if we may have no information about the existed binding
	if key != nil && !bytes.Equal(tb.Value, key) {
		return ErrorBadPromise
	}

	return nil
}
