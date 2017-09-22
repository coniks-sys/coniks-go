// Implements all consistency check operations done by a CONIKS client
// on data received from a CONIKS directory.
// These include data binding proof verification,
// and non-equivocation checks.

package client

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/auditor"
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
	// the auditor state stores the latest verified signed tree root
	// as well as the server's signing key
	*auditor.AudState
	Bindings map[string][]byte

	// extensions settings
	useTBs bool
	TBs    map[string]*protocol.TemporaryBinding
}

// New creates an instance of ConsistencyChecks using
// a CONIKS directory's pinned STR at epoch 0, or
// the consistency state read from persistent storage.
func New(savedSTR *protocol.DirSTR, useTBs bool, signKey sign.PublicKey) *ConsistencyChecks {
	// TODO: see #110
	if !useTBs {
		panic("[coniks] Currently the server is forced to use TBs")
	}
	a := auditor.New(signKey, savedSTR)
	cc := &ConsistencyChecks{
		AudState: a,
		Bindings: make(map[string][]byte),
		useTBs:   useTBs,
		TBs:      nil,
	}
	if useTBs {
		cc.TBs = make(map[string]*protocol.TemporaryBinding)
	}
	return cc
}

// CheckEquivocation checks for possible equivocation between
// an auditors' observed STRs and the client's own view.
// CheckEquivocation() first verifies the STR range received
// in msg if msg contains more than 1 STR, and
// then checks the most recent STR in msg against
// the cc.verifiedSTR.
// CheckEquivocation() is called when a client receives a response to a
// message.AuditingRequest from an auditor.
func (cc *ConsistencyChecks) CheckEquivocation(msg *protocol.Response) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	strs := msg.DirectoryResponse.(*protocol.STRHistoryRange)

	// verify the hashchain of the received STRs
	// if we get more than 1 in our range
	if len(strs.STR) > 1 {
		if err := cc.VerifySTRRange(strs.STR[0], strs.STR[1:]); err != nil {
			return err
		}
	}

	// TODO: if the auditor has returned a more recent STR,
	// should the client update its savedSTR? Should this
	// force a new round of monitoring?
	return cc.CheckSTRAgainstVerified(strs.STR[len(strs.STR)-1])
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
func (cc *ConsistencyChecks) HandleResponse(requestType int, msg *protocol.Response,
	uname string, key []byte) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	switch requestType {
	case protocol.RegistrationType, protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
		if _, ok := msg.DirectoryResponse.(*protocol.DirectoryProof); !ok {
			return protocol.ErrMalformedMessage
		}
	default:
		panic("[coniks] Unknown request type")
	}
	if err := cc.updateSTR(requestType, msg); err != nil {
		return err
	}
	if err := cc.checkConsistency(requestType, msg, uname, key); err != nil {
		return err
	}
	if err := cc.updateTBs(requestType, msg, uname, key); err != nil {
		return err
	}
	recvKey, _ := msg.GetKey()
	cc.Bindings[uname] = recvKey
	return nil
}

func (cc *ConsistencyChecks) updateSTR(requestType int, msg *protocol.Response) error {
	var str *protocol.DirSTR
	switch requestType {
	case protocol.RegistrationType, protocol.KeyLookupType:
		str = msg.DirectoryResponse.(*protocol.DirectoryProof).STR[0]
		// The initial STR is pinned in the client
		// so cc.verifiedSTR should never be nil
		// FIXME: use STR slice from Response msg
		if err := cc.AuditDirectory([]*protocol.DirSTR{str}); err != nil {
			return err
		}

	default:
		panic("[coniks] Unknown request type")
	}

	// And update the saved STR
	cc.Update(str)

	return nil
}

func (cc *ConsistencyChecks) checkConsistency(requestType int, msg *protocol.Response,
	uname string, key []byte) error {
	var err error
	switch requestType {
	case protocol.RegistrationType:
		err = cc.verifyRegistration(msg, uname, key)
	case protocol.KeyLookupType:
		err = cc.verifyKeyLookup(msg, uname, key)
	default:
		panic("[coniks] Unknown request type")
	}
	return err
}

func (cc *ConsistencyChecks) verifyRegistration(msg *protocol.Response,
	uname string, key []byte) error {
	df := msg.DirectoryResponse.(*protocol.DirectoryProof)
	// FIXME: should explicitly validate that
	// len(df.AP) == len(df.STR) == 1
	ap := df.AP[0]
	str := df.STR[0]

	proofType := ap.ProofType()
	switch {
	case msg.Error == protocol.ReqNameExisted && proofType == merkletree.ProofOfInclusion:
	case msg.Error == protocol.ReqNameExisted && proofType == merkletree.ProofOfAbsence && cc.useTBs:
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfAbsence:
	default:
		return protocol.ErrMalformedMessage
	}

	return verifyAuthPath(uname, key, ap, str)
}

func (cc *ConsistencyChecks) verifyKeyLookup(msg *protocol.Response,
	uname string, key []byte) error {
	df := msg.DirectoryResponse.(*protocol.DirectoryProof)
	// FIXME: should explicitly validate that
	// len(df.AP) == len(df.STR) == 1
	ap := df.AP[0]
	str := df.STR[0]

	proofType := ap.ProofType()
	switch {
	case msg.Error == protocol.ReqNameNotFound && proofType == merkletree.ProofOfAbsence:
	// FIXME: This would be changed when we support key changes
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfInclusion:
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfAbsence && cc.useTBs:
	default:
		return protocol.ErrMalformedMessage
	}

	return verifyAuthPath(uname, key, ap, str)
}

func verifyAuthPath(uname string, key []byte, ap *merkletree.AuthenticationPath, str *protocol.DirSTR) error {
	// verify VRF Index
	vrfKey := str.Policies.VrfPublicKey
	if !vrfKey.Verify([]byte(uname), ap.LookupIndex, ap.VrfProof) {
		return protocol.CheckBadVRFProof
	}

	if key == nil {
		// key is nil when the user does lookup for the first time.
		// Accept the received key as TOFU
		key = ap.Leaf.Value
	}

	switch err := ap.Verify([]byte(uname), key, str.TreeHash); err {
	case merkletree.ErrBindingsDiffer:
		return protocol.CheckBindingsDiffer
	case merkletree.ErrUnverifiableCommitment:
		return protocol.CheckBadCommitment
	case merkletree.ErrIndicesMismatch:
		return protocol.CheckBadLookupIndex
	case merkletree.ErrUnequalTreeHashes:
		return protocol.CheckBadAuthPath
	case nil:
		return nil
	default:
		panic("[coniks] Unknown error: " + err.Error())
	}
}

func (cc *ConsistencyChecks) updateTBs(requestType int, msg *protocol.Response,
	uname string, key []byte) error {
	if !cc.useTBs {
		return nil
	}
	switch requestType {
	case protocol.RegistrationType:
		df := msg.DirectoryResponse.(*protocol.DirectoryProof)
		if df.AP[0].ProofType() == merkletree.ProofOfAbsence {
			if err := cc.verifyReturnedPromise(df, key); err != nil {
				return err
			}
			cc.TBs[uname] = df.TB
		}
		return nil

	case protocol.KeyLookupType:
		df := msg.DirectoryResponse.(*protocol.DirectoryProof)
		ap := df.AP[0]
		str := df.STR[0]
		proofType := ap.ProofType()
		switch {
		case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfInclusion:
			if err := cc.verifyFulfilledPromise(uname, str, ap); err != nil {
				return err
			}
			delete(cc.TBs, uname)

		case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfAbsence:
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
func (cc *ConsistencyChecks) verifyFulfilledPromise(uname string, str *protocol.DirSTR,
	ap *merkletree.AuthenticationPath) error {
	// FIXME: Which epoch did this lookup happen in?
	if tb, ok := cc.TBs[uname]; ok {
		if !bytes.Equal(ap.LookupIndex, tb.Index) ||
			!bytes.Equal(ap.Leaf.Value, tb.Value) {
			return protocol.CheckBrokenPromise
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
func (cc *ConsistencyChecks) verifyReturnedPromise(df *protocol.DirectoryProof,
	key []byte) error {
	ap := df.AP[0]
	str := df.STR[0]
	tb := df.TB

	if tb == nil {
		return protocol.CheckBadPromise
	}

	// verify TB's Signature
	if !cc.Verify(tb.Serialize(str.Signature), tb.Signature) {
		return protocol.CheckBadSignature
	}

	if !bytes.Equal(tb.Index, ap.LookupIndex) {
		return protocol.CheckBadPromise
	}

	// key could be nil if we have no information about
	// the existed binding (TOFU).
	if key != nil && !bytes.Equal(tb.Value, key) {
		return protocol.CheckBindingsDiffer
	}
	return nil
}
