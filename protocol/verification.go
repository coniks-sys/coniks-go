package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

func verifyAuthPath(uname string, key []byte,
	ap *m.AuthenticationPath,
	str *m.SignedTreeRoot) ErrorCode {

	// verify VRF Index
	vrfKey := vrf.PublicKey(str.Policies.VrfPublicKey)
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return ErrorBadVRFProof
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) { /* proof of inclusion */
		// verify name-to-key binding
		if !ap.VerifyBinding(key) {
			return ErrorBadBinding
		}
		// verify commitment
		if !ap.Leaf.Commitment.Verify([]byte(uname), ap.Leaf.Value) {
			return ErrorBadCommitment
		}
	}

	// verify auth path
	if !ap.Verify(str.TreeHash) {
		return ErrorBadMapping
	}

	return Passed
}

func verifySTR(signKey sign.PublicKey,
	str *m.SignedTreeRoot,
	curEp uint64, savedSTR []byte) ErrorCode {

	// verify STR's signature
	if !signKey.Verify(str.Serialize(), str.Signature) {
		return ErrorBadSignature
	}

	// verify hash chain
	if savedSTR == nil ||
		(str.Epoch == curEp && !bytes.Equal(savedSTR, str.Signature)) ||
		(str.Epoch > 0 && !str.VerifyHashChain(savedSTR)) {
		return ErrorBadSTR
	}

	return Passed
}
