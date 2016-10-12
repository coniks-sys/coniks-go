package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

type ProofType int

const (
	InvalidProof ProofType = iota
	ProofOfAbsence
	ProofOfInclusion
)

// ConiksClient stores the current state of a CONIKS client.
// This includes the current epoch and SignedTreeRoot value,
// as well as directory's configurations
// (e.g., wherether the TemporaryBinding extension is being used or not).
// This struct also stores the verification results including
// the type of returned proof.
// The client should create a new ConiksClient instance only once,
// when she registers her binding with a ConiksDirectory.
// This ConiksClient instance then will be used to verify
// the returned response from a ConiksDirectory.
type ConiksClient struct {
	CurrentEpoch uint64
	SavedSTR     []byte

	// verification results
	ProofType          ProofType
	VerificationResult ErrorCode

	// extensions settings
	isUseTBs bool
	TBs      []*m.TemporaryBinding

	// signing key
	// TODO: should we pin the signing key and vrf key in the client? see #47
	signKey sign.PublicKey
}

func NewConiksClient(savedSTR []byte, isUseTBs bool, signKey sign.PublicKey) *ConiksClient {
	return &ConiksClient{
		CurrentEpoch: 0,
		SavedSTR:     savedSTR,
		isUseTBs:     isUseTBs,
		signKey:      signKey,
	}
}

func (cs *ConiksClient) Verify(msg *Response, uname string, key []byte) {
	switch msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		cs.verifyDirectoryProof(
			msg.DirectoryResponse.(*DirectoryProof), uname, key)
	case *DirectoryProofs:
		cs.verifyDirectoryProofs(
			msg.DirectoryResponse.(*DirectoryProofs), uname, key)
	}
}

func (cs *ConiksClient) verifyDirectoryProof(df *DirectoryProof, uname string, key []byte) {
	ap := df.AP
	str := df.STR
	tb := df.TB

	if cs.VerificationResult = cs.verifySTR(str); cs.VerificationResult != Passed {
		return
	}

	if cs.ProofType, cs.VerificationResult = cs.verifyAuthPath(uname, key,
		ap, str); cs.VerificationResult != Passed {
		return
	}

	if tb != nil {
		// verify TB's Signature
		if !cs.signKey.Verify(tb.Serialize(str.Signature), tb.Signature) {
			cs.VerificationResult = ErrorBadSignature
			return
		}

		// verify TB's VRF index
		if !bytes.Equal(tb.Index, ap.LookupIndex) {
			cs.VerificationResult = ErrorBadIndex
			return
		}

		cs.TBs = append(cs.TBs, tb)
	}

	if cs.VerificationResult = cs.verifyIssuedPromise(str.Epoch, ap); cs.VerificationResult != Passed {
		return
	}

	cs.VerificationResult = Passed

	// re-assign new state for the client
	if str.Epoch > cs.CurrentEpoch {
		cs.CurrentEpoch++
		cs.SavedSTR = str.Signature
	}
}

func (cs *ConiksClient) verifyDirectoryProofs(dfs *DirectoryProofs, uname string, key []byte) {
	// TODO: fix me
	cs.VerificationResult = Passed
}

func (cs *ConiksClient) verifyAuthPath(uname string, key []byte,
	ap *m.AuthenticationPath,
	str *m.SignedTreeRoot) (ProofType, ErrorCode) {
	proofType := ProofOfAbsence

	// verify VRF Index
	vrfKey := vrf.PublicKey(str.Policies.VrfPublicKey)
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return InvalidProof, ErrorBadVRFProof
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) { /* proof of inclusion */
		// verify name-to-key binding
		// key is nil when the user does lookup for the first time
		if key != nil && !ap.VerifyBinding(key) {
			return InvalidProof, ErrorBadBinding
		}
		// verify commitment
		if !ap.Leaf.Commitment.Verify([]byte(uname), ap.Leaf.Value) {
			return InvalidProof, ErrorBadCommitment
		}
		proofType = ProofOfInclusion
	}

	// verify auth path
	if !ap.Verify(str.TreeHash) {
		return InvalidProof, ErrorBadMapping
	}

	return proofType, Passed
}

func (cs *ConiksClient) verifySTR(str *m.SignedTreeRoot) ErrorCode {
	// verify STR's signature
	if !cs.signKey.Verify(str.Serialize(), str.Signature) {
		return ErrorBadSignature
	}

	// verify hash chain
	if (str.Epoch == cs.CurrentEpoch && bytes.Equal(cs.SavedSTR, str.Signature)) ||
		(str.Epoch == cs.CurrentEpoch+1 && str.VerifyHashChain(cs.SavedSTR)) {
		return Passed
	}
	return ErrorBadSTR
}

func (cs *ConiksClient) verifyIssuedPromise(epoch uint64, ap *m.AuthenticationPath) ErrorCode {
	if cs.isUseTBs {
		for _, tb := range cs.TBs {
			if tb.IssuedEpoch == epoch {
				if !tb.Verify(epoch, ap) {
					return ErrorBreakPromise
				}

				// TODO: delete issued promise
			}
		}
	}
	return Passed
}
