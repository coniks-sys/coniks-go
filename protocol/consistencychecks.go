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
	// TODO: should we pin the signing key in the client? see #47
	signKey sign.PublicKey
}

// NewCC creates an instance of ConsistencyChecks using
// the pinning directory's STR at epoch 0.
func NewCC(savedSTR []byte, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {

	// Fix me: see #110
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

// Verify verifies the directory's response for a request.
// It first verifies the directory's returned status code of the request.
// If the status code is not in ErrorResponses array, it means
// the directory has successfully handled the request.
// The verifier will then verify the consistency state of the response,
// and finally, it verifies the returned proof type
// according to the request type.
// This will also update the consistency state if the check is passed.
func (cc *ConsistencyChecks) Verify(requestType int, msg *Response,
	uname string, key []byte) ErrorCode {

	if ErrorResponses[msg.Error] {
		return msg.Error
	}

	var verifResult error
	var proofType int

	switch msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		proofType, verifResult = cc.verifyDirectoryProof(
			msg.DirectoryResponse.(*DirectoryProof), uname, key)
	case *DirectoryProofs:
		proofType, verifResult = cc.verifyDirectoryProofs(
			msg.DirectoryResponse.(*DirectoryProofs), uname, key)
	}

	if verifResult != nil {
		return verifResult.(ErrorCode)
	}

	switch requestType {
	case RegistrationType:
		if msg.Error == ErrorNameExisted &&
			proofType == proofOfInclusion {
			return PassedWithAProofOfInclusion
		} else if msg.Error == Success &&
			proofType == proofOfAbsence {
			return PassedWithAProofOfAbsence
		}
		return cc.verifyProofTypeUsingPromises(msg.Error, proofType)

	case KeyLookupType:
		if msg.Error == ErrorNameNotFound &&
			proofType == proofOfAbsence {
			return PassedWithAProofOfAbsence
		} else if msg.Error == Success &&
			proofType == proofOfInclusion {
			return PassedWithAProofOfInclusion
		}
		return cc.verifyProofTypeUsingPromises(msg.Error, proofType)

	case MonitoringType:
		if proofType == proofOfAbsence {
			return ErrorBadProofType
		}
		return PassedWithAProofOfInclusion

	case KeyLookupInEpochType:
		// TODO: fix me

	}

	// this return should be unreachable
	// unless the developers mistakenly passed an invalid request type.
	return ErrorMalformedClientMessage
}

func (cc *ConsistencyChecks) verifyDirectoryProof(df *DirectoryProof,
	uname string, key []byte) (proofType int, verifResult error) {

	verifResult = nil
	proofType = invalidProof

	ap := df.AP
	str := df.STR
	tb := df.TB

	if verifResult = cc.verifySTR(str); verifResult != nil {
		return
	}

	if proofType, verifResult = cc.verifyAuthPath(uname, key,
		ap, str); verifResult != nil {
		return
	}

	if verifResult = cc.verifyReturnedPromise(tb, uname, key, str, ap); verifResult != nil {
		return
	}

	if verifResult = cc.verifyFulfilledPromise(uname, str, ap); verifResult != nil {
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
	// TODO: fix me
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
	if (str.Epoch == cc.CurrentEpoch && bytes.Equal(cc.SavedSTR, str.Signature)) ||
		(str.Epoch == cc.CurrentEpoch+1 && str.VerifyHashChain(cc.SavedSTR)) {
		return nil
	}
	return ErrorBadSTR
}

// verifyReturnedPromise verifies the returned TB
// included in the directory's response.
func (cc *ConsistencyChecks) verifyReturnedPromise(tb *m.TemporaryBinding,
	uname string, key []byte,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {

	if cc.useTBs && tb != nil {
		// the client should receive a signed promise iff
		// the server returns a proof of absence
		if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
			return ErrorMalformedDirectoryMessage
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
		if !bytes.Equal(tb.Value, key) {
			return ErrorBadPromise
		}

		cc.TBs[uname] = tb
	}

	return nil
}

// verifyFulfilledPromise verifies issued TBs was inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string,
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	if cc.useTBs {
		for name, tb := range cc.TBs {
			if cc.CurrentEpoch+1 == str.Epoch &&
				name == uname {
				if !tb.Verify(ap) {
					return ErrorBrokenPromise
				}
				delete(cc.TBs, uname)
			} else if cc.CurrentEpoch < str.Epoch {
				// clear all issued promises since they have been verified
				// or the client has missed some epochs
				// TODO: should verify when we introduce KeyLookupInEpoch
				// and monitoring with missed epochs,
				// see: https://github.com/coniks-sys/coniks-go/pull/74#discussion_r84930999
				// and: https://github.com/coniks-sys/coniks-go/pull/74#discussion_r84501211
				delete(cc.TBs, name)
			}
			// keep current epoch's returned promises
			// for future verifications
		}
	}
	return nil
}

// verifyProofTypeUsingPromises verifies the returned proof type
// and the returned error code when signed promises extension is enabled.
// See #110.
func (cc *ConsistencyChecks) verifyProofTypeUsingPromises(e ErrorCode, proofType int) ErrorCode {
	if cc.useTBs {
		// these checks mean the requested binding wasn't included in the latest STR
		// but was being held in the temporary binding array.
		if (e == ErrorNameExisted && proofType == proofOfAbsence) ||
			(e == Success && proofType == proofOfAbsence) {
			return PassedWithAProofOfAbsence
		}
	}

	return ErrorBadProofType
}
