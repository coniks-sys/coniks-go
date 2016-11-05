// Implements all consistency check operations done by a CONIKS client
// on data received from a CONIKS directory.
// These include data binding proof verification,
// and non-equivocation checks.

package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

const (
	invalidProof int = iota
	proofOfAbsence
	proofOfInclusion
)

// ConsistencyChecks stores the current consistency check
// state of a CONIKS client. This includes the current epoch
// and SignedTreeRoot value, as well as directory's policies
// (e.g., wherether the TemporaryBinding extension is being used or not)
// The client should create a new ConsistencyChecks instance only once,
// when she registers her binding with a ConiksDirectory.
// This ConsistencyChecks instance then will be used to verify
// the returned responses from the ConiksDirectory.
type ConsistencyChecks struct {
	SavedSTR *m.SignedTreeRoot

	// extensions settings
	useTBs bool
	TBs    map[string]*m.TemporaryBinding

	// signing key
	signKey sign.PublicKey
}

// NewCC creates an instance of ConsistencyChecks using
// the pinning directory's STR at epoch 0 or
// the consistency state read from a persistent storage.
func NewCC(savedSTR *m.SignedTreeRoot, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {

	// TODO: see #110
	if !useTBs {
		panic("Currently the server is forced to use TBs")
	}

	cc := &ConsistencyChecks{
		SavedSTR: savedSTR,
		useTBs:   useTBs,
		signKey:  signKey,
	}

	if useTBs {
		cc.TBs = make(map[string]*m.TemporaryBinding)
	}
	return cc
}

// UpdateConsistency verifies the directory's response for a request and
// updates the current state if all the verifications are passed.
// It first verifies the directory's returned status code of the request.
// If the status code is not in the ErrorResponses array, it means
// the directory has successfully handled the request.
// The verifier will then verify the consistency state of the response.
func (cc *ConsistencyChecks) UpdateConsistency(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	if ErrorResponses[msg.Error] {
		return msg.Error
	}

	var str *m.SignedTreeRoot
	var err error

	switch requestType {
	case RegistrationType:
		str, err = cc.verifyRegistration(requestType, msg, uname, key)
	case KeyLookupType:
		str, err = cc.verifyKeyLookup(requestType, msg, uname, key)
	case MonitoringType:
	case KeyLookupInEpochType:
	default:
		panic("[coniks] Unknown request type")
	}

	// update the state
	if err == PassedWithAProofOfAbsence ||
		err == PassedWithAProofOfInclusion {
		cc.SavedSTR = str
	}

	return err.(ErrorCode)
}

func (cc *ConsistencyChecks) verifyRegistration(requestType int,
	msg *Response, uname string, key []byte) (*m.SignedTreeRoot, error) {

	df, ok := msg.DirectoryResponse.(*DirectoryProof)
	if !ok {
		return nil, ErrorMalformedDirectoryMessage
	}

	ap := df.AP
	str := df.STR

	// 1. verify STR
	if err := cc.verifySTR(str); err != nil {
		return nil, err
	}

	// 2. verify Auth path
	proofType, err := cc.verifyAuthPath(uname, key, ap, str)
	if err != nil {
		return nil, err
	}

	// 3. verify (response code, proof type) pair
	switch {
	case msg.Error == ErrorNameExisted:
	case msg.Error == Success && proofType == proofOfAbsence:
	default:
		return nil, ErrorMalformedDirectoryMessage
	}

	// 4. verify returned promise
	if err := cc.verifyReturnedPromise(requestType,
		msg.Error, df, uname, key); err != nil {
		return nil, err
	}

	if proofType == proofOfAbsence {
		return str, PassedWithAProofOfAbsence
	}
	return str, PassedWithAProofOfInclusion
}

func (cc *ConsistencyChecks) verifyKeyLookup(requestType int,
	msg *Response, uname string, key []byte) (*m.SignedTreeRoot, error) {

	df, ok := msg.DirectoryResponse.(*DirectoryProof)
	if !ok {
		return nil, ErrorMalformedDirectoryMessage
	}

	ap := df.AP
	str := df.STR

	// 1. verify STR
	if err := cc.verifySTR(str); err != nil {
		return nil, err
	}

	// 2. verify Auth path
	proofType, err := cc.verifyAuthPath(uname, key, ap, str)
	if err != nil {
		return nil, err
	}

	// 3. verify (response code, proof type) pair
	switch {
	case msg.Error == ErrorNameNotFound && proofType == proofOfAbsence:
	case msg.Error == Success:
	default:
		return nil, ErrorMalformedDirectoryMessage
	}

	// determine which kind of TB's verification we should do
	// based on the response code and proof type
	if msg.Error == Success && proofType == proofOfAbsence {
		// 4.1 verify returned promise
		if err := cc.verifyReturnedPromise(requestType,
			msg.Error, df, uname, key); err != nil {
			return nil, err
		}
	} else {
		// 4.2 verify fulfilled promise
		if err := cc.verifyFulfilledPromise(uname, str, ap); err != nil {
			return nil, err
		}
	}

	if proofType == proofOfAbsence {
		return str, PassedWithAProofOfAbsence
	}
	return str, PassedWithAProofOfInclusion
}

func (cc *ConsistencyChecks) verifyAuthPath(uname string, key []byte,
	ap *m.AuthenticationPath,
	str *m.SignedTreeRoot) (int, error) {
	proofType := proofOfAbsence

	// verify VRF Index
	vrfKey := vrf.PublicKey(str.Policies.VrfPublicKey)
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return invalidProof, ErrorBadVRFProof
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) { // proof of inclusion */
		// verify name-to-key binding
		// key is nil when the user does lookup for the first time
		if key != nil && !ap.VerifyBinding(key) {
			return invalidProof, ErrorBadBinding
		}
		// verify commitment
		if !ap.Leaf.Commitment.Verify([]byte(uname), ap.Leaf.Value) {
			return invalidProof, ErrorBadCommitment
		}
		proofType = proofOfInclusion
	}

	// verify auth path
	if !ap.Verify(str.TreeHash) {
		return invalidProof, ErrorBadAuthPath
	}

	return proofType, nil
}

func (cc *ConsistencyChecks) verifySTR(str *m.SignedTreeRoot) error {
	// verify STR's signature
	if !cc.signKey.Verify(str.Serialize(), str.Signature) {
		return ErrorBadSignature
	}

	// verify hash chain
	// TODO: clearly verify which is the client's actual expectation.
	// See #81
	if (str.Epoch == cc.SavedSTR.Epoch && bytes.Equal(cc.SavedSTR.Signature, str.Signature)) ||
		(str.Epoch == cc.SavedSTR.Epoch+1 && str.VerifyHashChain(cc.SavedSTR.Signature)) {
		return nil
	}

	// TODO: verify the directory's policies as well. See #115
	return ErrorBadSTR
}

// verifyFulfilledPromise verifies issued TBs was inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	if !cc.useTBs {
		return nil
	}

	if cc.SavedSTR.Epoch+1 != str.Epoch {
		return nil
	}

	tb := cc.TBs[uname]
	if tb != nil {
		if !tb.Verify(ap) {
			return ErrorBrokenPromise
		}
		delete(cc.TBs, uname)
	}
	return nil
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
func (cc *ConsistencyChecks) verifyReturnedPromise(requestType int,
	responseCode ErrorCode, df *DirectoryProof,
	uname string, key []byte) error {
	if !cc.useTBs {
		return nil
	}

	ap := df.AP
	str := df.STR
	tb := df.TB

	// the client should receive a signed promise iff
	// the directory returns a proof of absence
	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		if tb != nil {
			// the directory returned a proof of inclusion
			// _and_ a promise
			return ErrorMalformedDirectoryMessage
		}
		return nil
	}

	if tb == nil {
		if (requestType == RegistrationType) ||
			(requestType == KeyLookupType && responseCode == Success) {
			return ErrorBadPromise
		}
		return nil
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

	// get a valid promise
	cc.TBs[uname] = tb

	return nil
}
