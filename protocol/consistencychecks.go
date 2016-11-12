// Implements all consistency check operations done by a CONIKS client
// on data received from a CONIKS directory.
// These include data binding proof verification,
// and non-equivocation checks.

package protocol

import (
	"bytes"
	"reflect"
	"time"

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
	// Timestamp indicates the time when the SavedSTR updated.
	Timestamp m.Timestamp
	SavedSTR  *m.SignedTreeRoot

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
		panic("[coniks] Currently the server is forced to use TBs")
	}

	cc := &ConsistencyChecks{
		Timestamp: m.Timestamp(time.Now().Unix()),
		SavedSTR:  savedSTR,
		useTBs:    useTBs,
		signKey:   signKey,
	}

	if useTBs {
		cc.TBs = make(map[string]*TemporaryBinding)
	}
	return cc
}

// UpdateConsistency verifies the directory's response for a request.
// It will also update the state if the requestType is
// either RegistrationType or MonitoringType.
// It first verifies the directory's returned status code of the request.
// If the status code is not in the ErrorResponses array, it means
// the directory has successfully handled the request.
// The verifier will then verify the consistency state of the response.
// This will panic if it is called with an int
// which isn't a valid/known request-type.
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
		err = cc.verifyKeyLookup(requestType, msg, uname, key)

	case MonitoringType:
	case KeyLookupInEpochType:
	default:
		panic("[coniks] Unknown request type")
	}

	if err == Passed &&
		requestType == RegistrationType || requestType == MonitoringType {
		// update the state
		cc.Timestamp = m.Timestamp(time.Now().Unix())
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
	tb := df.TB

	interval := m.Timestamp(time.Now().Unix()) - cc.Timestamp
	if interval < 0 {
		panic("[coniks] Malformed consistency state.")
	} else if interval <= cc.SavedSTR.Policies.EpochDeadline { // same str
		if err := cc.verifySTR(str); err != nil {
			return nil, err
		}
	} else { // new str
		if err := cc.verifySTRConsistency(cc.SavedSTR, str); err != nil {
			return nil, err
		}
	}

	proofType := ap.ProofType()
	switch {
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfInclusion && tb == nil:
	case msg.Error == ErrorNameExisted && proofType == m.ProofOfAbsence:
	case msg.Error == Success && proofType == m.ProofOfAbsence:
	default:
		return nil, ErrorMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return nil, err
	}

	if proofType == m.ProofOfAbsence {
		if err := cc.verifyReturnedPromise(df, uname, key); err != nil {
			return nil, err
		}
	}

	return str, Passed
}

func (cc *ConsistencyChecks) verifyKeyLookup(requestType int,
	msg *Response, uname string, key []byte) error {

	df, ok := msg.DirectoryResponse.(*DirectoryProof)
	if !ok {
		return ErrorMalformedDirectoryMessage
	}

	ap := df.AP
	str := df.STR
	tb := df.TB

	if err := cc.verifySTR(str); err != nil {
		return err
	}

	proofType := ap.ProofType()
	switch {
	case msg.Error == Success && proofType == m.ProofOfInclusion && tb == nil:
	case msg.Error == Success && proofType == m.ProofOfAbsence:
	case msg.Error == ErrorNameNotFound && proofType == m.ProofOfAbsence:
	default:
		return ErrorMalformedDirectoryMessage
	}

	if err := verifyAuthPath(uname, key, ap, str); err != nil {
		return err
	}

	// determine which kind of TB's verification we should do
	// based on the response code and proof type
	if msg.Error == Success && proofType == m.ProofOfAbsence {
		if err := cc.verifyReturnedPromise(df, uname, key); err != nil {
			return err
		}
	} else { // (msg.Error != Success || proofType != m.ProofOfAbsence)
		if err := cc.verifyFulfilledPromise(uname, str, ap); err != nil {
			return err
		}
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

// verifyFulfilledPromise verifies issued TBs were inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	if !cc.useTBs {
		return nil
	}

	if cc.SavedSTR.Epoch != str.Epoch {
		panic("[coniks] Malformed consistency state. Probably should do self monitoring first to update the state.")
	}

	tb := cc.TBs[uname]
	if tb != nil {
		// compare TB's index with authentication path's index
		if !bytes.Equal(ap.LookupIndex, tb.Index) ||
			!bytes.Equal(ap.Leaf.Value, tb.Value) {
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
// These above checks should be performed before calling this method.
func (cc *ConsistencyChecks) verifyReturnedPromise(df *DirectoryProof,
	uname string, key []byte) error {
	if !cc.useTBs {
		return nil
	}

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

	// get a valid promise
	cc.TBs[uname] = tb

	return nil
}
