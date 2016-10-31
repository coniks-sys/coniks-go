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
	CurrentEpoch uint64
	SavedSTR     []byte

	// extensions settings
	useTBs bool
	TBs    map[string]*m.TemporaryBinding

	// signing key
	signKey sign.PublicKey
}

// NewCC creates an instance of ConsistencyChecks using
// the pinning directory's STR at epoch 0.
func NewCC(savedSTR []byte, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {

	// TODO: see #110
	if !useTBs {
		panic("Currently the server is forced to use TBs")
	}

	cc := &ConsistencyChecks{
		CurrentEpoch: 0,
		SavedSTR:     savedSTR,
		useTBs:       useTBs,
		signKey:      signKey,
	}

	if useTBs {
		cc.TBs = make(map[string]*m.TemporaryBinding)
	}
	return cc
}

// clone makes a copy of the current consistency state.
func (cc *ConsistencyChecks) clone() *ConsistencyChecks {
	newCC := &ConsistencyChecks{
		CurrentEpoch: cc.CurrentEpoch,
		SavedSTR:     cc.SavedSTR,
		useTBs:       cc.useTBs,
		signKey:      cc.signKey,
	}

	if cc.useTBs {
		newCC.TBs = make(map[string]*m.TemporaryBinding)
		for k, v := range cc.TBs {
			newCC.TBs[k] = v
		}
	}

	return newCC
}

func (cc *ConsistencyChecks) update(updated *ConsistencyChecks) {
	cc.CurrentEpoch = updated.CurrentEpoch
	cc.SavedSTR = updated.SavedSTR
	cc.TBs = updated.TBs
}

// Verify verifies the directory's response for a request and
// updates the current state if all the verifications are successful.
// It makes a copy of the current state and does verifications
// using the cloned state. To verify the directory's response,
// it first verifies the directory's returned status code of the request.
// If the status code is not in ErrorResponses array, it means
// the directory has successfully handled the request.
// The verifier will then verify the consistency state of the response.
// During the verifications, the cloned state would be modified.
// This cloned state will be used to update the original
// state if all the verifications are passed, otherwise it will be discarded.
func (cc *ConsistencyChecks) Verify(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {
	if ErrorResponses[msg.Error] {
		return msg.Error
	}

	var verifResult error
	var proofType int

	cloneCC := cc.clone()
	switch msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		proofType, verifResult = cloneCC.verifyDirectoryProof(requestType,
			msg.Error, msg.DirectoryResponse.(*DirectoryProof), uname, key)

	case *DirectoryProofs:
		proofType, verifResult = cloneCC.verifyDirectoryProofs(
			msg.DirectoryResponse.(*DirectoryProofs), uname, key)
	}

	if verifResult != nil {
		return verifResult.(ErrorCode)
	}
	cc.update(cloneCC)

	if proofType == proofOfAbsence {
		return PassedWithAProofOfAbsence
	}
	return PassedWithAProofOfInclusion
}

func (cc *ConsistencyChecks) verifyDirectoryProof(requestType int,
	responseCode ErrorCode, df *DirectoryProof,
	uname string, key []byte) (proofType int, verifResult error) {

	verifResult = nil
	proofType = invalidProof

	ap := df.AP
	str := df.STR

	if verifResult = cc.verifySTR(str); verifResult != nil {
		return
	}

	if proofType, verifResult = cc.verifyAuthPath(uname, key,
		ap, str); verifResult != nil {
		return
	}

	// validates the (response code, proof type) according to the request type.
	switch requestType {
	case RegistrationType:
		if responseCode != ErrorNameExisted &&
			(responseCode != Success || proofType != proofOfAbsence) {
			return invalidProof, ErrorMalformedDirectoryMessage
		}

	case KeyLookupType:
		if responseCode != Success &&
			(responseCode != ErrorNameNotFound || proofType != proofOfAbsence) {
			return invalidProof, ErrorMalformedDirectoryMessage
		}

	default:
		panic("[coniks] Unknown request type")
	}

	if verifResult = cc.verifySignedPromise(requestType,
		responseCode, df, uname, key); verifResult != nil {
		return
	}

	// re-assign new state for the client
	if str.Epoch == cc.CurrentEpoch+1 {
		cc.CurrentEpoch++
		cc.SavedSTR = str.Signature
	}
	return
}

func (cc *ConsistencyChecks) verifyDirectoryProofs(dfs *DirectoryProofs,
	uname string, key []byte) (int, error) {
	// TODO: implement verifications for multi ranges of epoch
	return invalidProof, nil
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
	if (str.Epoch == cc.CurrentEpoch && bytes.Equal(cc.SavedSTR, str.Signature)) ||
		(str.Epoch == cc.CurrentEpoch+1 && str.VerifyHashChain(cc.SavedSTR)) {
		return nil
	}
	return ErrorBadSTR
}

// verifySignedPromise checks if the returned response is match
// with the directory's policy. Then it calls verifyFulfilledPromise
// to verify whether issued TBs was inserted in the directory
// as promised. Finally, it verifies the returned promise
// based on the request type. Note that the directory returns a promise
// iff the returned proof is a proof of absence.
// 	If the request is a registration, and
// 	- the request is successful, then the directory should return a promise for the new binding.
// 	- the request is failed because of ErrorNameExisted, then the directory should return a promise for that existed binding.
//
// 	If the request is a key lookup, and
// 	- the request is successful, then the directory should return a promise for the lookup binding.
func (cc *ConsistencyChecks) verifySignedPromise(requestType int,
	responseCode ErrorCode, df *DirectoryProof,
	uname string, key []byte) error {
	ap := df.AP
	str := df.STR
	tb := df.TB

	if !cc.useTBs {
		if tb != nil {
			// this violates the directory's policy.
			return ErrorMalformedDirectoryMessage
		}
		return nil
	}

	if verifResult := cc.verifyFulfilledPromise(uname, str, ap); verifResult != nil {
		return verifResult
	}

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

	switch requestType {
	case RegistrationType:
		if responseCode == ErrorNameExisted {
			// ignore the key value verification since we may have no information about that existed binding.
			if verifResult := cc.verifyReturnedPromise(tb, uname, nil, str, ap); verifResult != nil {
				return verifResult
			}
		} else if responseCode == Success {
			// this promise should be our binding
			if verifResult := cc.verifyReturnedPromise(tb, uname, key, str, ap); verifResult != nil {
				return verifResult
			}
		}

	case KeyLookupType:
		if responseCode == Success {
			if verifResult := cc.verifyReturnedPromise(tb, uname, key, str, ap); verifResult != nil {
				return verifResult
			}
		}
	}

	return nil
}

// verifyReturnedPromise verifies the returned TB
// included in the directory's response.
func (cc *ConsistencyChecks) verifyReturnedPromise(tb *m.TemporaryBinding,
	uname string, key []byte,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {

	// verify TB's Signature
	if !cc.signKey.Verify(tb.Serialize(str.Signature), tb.Signature) {
		return ErrorBadSignature
	}

	// verify TB's VRF index
	if !bytes.Equal(tb.Index, ap.LookupIndex) {
		return ErrorBadIndex
	}

	// verify TB's value
	if key != nil && !bytes.Equal(tb.Value, key) {
		return ErrorBadPromise
	}

	cc.TBs[uname] = tb

	return nil
}

// verifyFulfilledPromise verifies issued TBs was inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	for name, tb := range cc.TBs {
		if cc.CurrentEpoch+1 == str.Epoch &&
			name == uname {
			if !tb.Verify(ap) {
				return ErrorBrokenPromise
			}
			delete(cc.TBs, uname)
		} else if cc.CurrentEpoch < str.Epoch {
			// TODO: should verify when we introduce KeyLookupInEpoch
			// and monitoring with missed epochs,
			// see: https://github.com/coniks-sys/coniks-go/pull/74#discussion_r84930999
			// and: https://github.com/coniks-sys/coniks-go/pull/74#discussion_r84501211
			delete(cc.TBs, name)
		}
		// keep current epoch's returned promises
		// for future verifications
	}
	return nil
}
