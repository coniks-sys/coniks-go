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
	isUseTBs bool
	TBs      []*m.TemporaryBinding

	// signing key
	// TODO: should we pin the signing key in the client? see #47
	signKey sign.PublicKey
}

// NewCC creates an instance of ConsistencyChecks using
// the pinning directory's STR at epoch 0.
func NewCC(savedSTR []byte, isUseTBs bool, signKey sign.PublicKey) *ConsistencyChecks {
	return &ConsistencyChecks{
		CurrentEpoch: 0,
		SavedSTR:     savedSTR,
		isUseTBs:     isUseTBs,
		signKey:      signKey,
	}
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

	var verificationResult error
	var proofType int

	switch msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		proofType, verificationResult = cc.verifyDirectoryProof(
			msg.DirectoryResponse.(*DirectoryProof), uname, key)
	case *DirectoryProofs:
		proofType, verificationResult = cc.verifyDirectoryProofs(
			msg.DirectoryResponse.(*DirectoryProofs), uname, key)
	}

	if verificationResult != nil {
		return verificationResult.(ErrorCode)
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
		return cc.verifyProofTypeWithTB(msg.Error, proofType)

	case KeyLookupType:
		if msg.Error == ErrorNameNotFound &&
			proofType == proofOfAbsence {
			return PassedWithAProofOfAbsence
		} else if msg.Error == Success &&
			proofType == proofOfInclusion {
			return PassedWithAProofOfInclusion
		}
		return cc.verifyProofTypeWithTB(msg.Error, proofType)

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
	uname string, key []byte) (proofType int, verificationResult error) {

	verificationResult = nil
	proofType = invalidProof

	ap := df.AP
	str := df.STR
	tb := df.TB

	if verificationResult = cc.verifySTR(str); verificationResult != nil {
		return
	}

	if proofType, verificationResult = cc.verifyAuthPath(uname, key,
		ap, str); verificationResult != nil {
		return
	}

	if verificationResult = cc.verifyReturnedPromise(tb, str, ap); verificationResult != nil {
		return
	}

	if verificationResult = cc.verifyFulfilledPromise(str, ap); verificationResult != nil {
		return
	}

	// re-assign new state for the client
	if str.Epoch > cc.CurrentEpoch {
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
	str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	if cc.isUseTBs && tb != nil {
		// verify TB's Signature
		if !cc.signKey.Verify(tb.Serialize(str.Signature), tb.Signature) {
			return ErrorBadSignature
		}

		// verify TB's VRF index
		if !bytes.Equal(tb.Index, ap.LookupIndex) {
			return ErrorBadIndex
		}

		cc.TBs = append(cc.TBs, tb)
	}

	return nil
}

// verifyFulfilledPromise verifies issued TBs was inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(str *m.SignedTreeRoot,
	ap *m.AuthenticationPath) error {
	if cc.isUseTBs {
		backed := cc.TBs[:0]
		for _, tb := range cc.TBs {
			if cc.CurrentEpoch+1 == str.Epoch {
				if !tb.Verify(ap) {
					return ErrorBrokenPromise
				}
			} else if cc.CurrentEpoch == str.Epoch {
				// keep current epoch's returned promises
				// for future verifications
				backed = append(backed, tb)
			}
		}

		// clear all issued promises since they have been verified
		// or the client has missed some epochs
		cc.TBs = backed
	}
	return nil
}

func (cc *ConsistencyChecks) verifyProofTypeWithTB(statusCode ErrorCode, proofType int) ErrorCode {
	if (statusCode == ErrorNameExisted && proofType == proofOfAbsence) ||
		(statusCode == ErrorNameNotFound && proofType == proofOfAbsence) {
		return PassedWithAProofOfAbsence
	}

	return ErrorBadProofType
}
