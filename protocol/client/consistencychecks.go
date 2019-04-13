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

// UpdateSTR verifies the received `protocol.STRHistoryRange`
// and update the consistency state regardless of
// whether the checks pass / fail, since a response message contains
// cryptographic proof of having been issued nonetheless.
func (cc *ConsistencyChecks) UpdateSTR(msg *protocol.Response) error {
	if err := msg.Validate(); err != nil {
		return err
	}

	var strs []*protocol.DirSTR
	if history, ok := msg.DirectoryResponse.(*protocol.STRHistoryRange); !ok {
		return protocol.ErrMalformedMessage
	} else {
		strs = history.STR
	}

	err := cc.AuditDirectory(strs)
	// And update the saved STR
	cc.Update(strs[len(strs)-1])
	return err
}

// VerifyConsistency verifies the consistency of the given
// user's profile and updates the profile data if all checks are passed.
func (cc *ConsistencyChecks) VerifyConsistency(profile *Profile,
	requestType int, msg *protocol.Response) error {
	if err := msg.Validate(); err != nil {
		return err
	}
	if _, ok := msg.DirectoryResponse.(*protocol.DirectoryProof); !ok {
		return protocol.ErrMalformedMessage
	}

	switch requestType {
	case protocol.RegistrationType:
		if err := cc.verifyRegistration(profile, msg); err != nil {
			return err
		}
	case protocol.KeyLookupInEpochType:
		if err := cc.verifyKeyLookup(profile, msg); err != nil {
			return err
		}
	default:
		panic("[coniks] Unknown request type")
	}

	return cc.updateTBs(profile, requestType, msg)
}

func (cc *ConsistencyChecks) verifyRegistration(profile *Profile,
	msg *protocol.Response) error {
	df := msg.DirectoryResponse.(*protocol.DirectoryProof)
	if len(df.AP) != 1 {
		return protocol.ErrMalformedMessage
	}

	ap := df.AP[0]
	proofType := ap.ProofType()
	switch {
	case msg.Error == protocol.ReqNameExisted && proofType == merkletree.ProofOfInclusion:
	case msg.Error == protocol.ReqNameExisted && proofType == merkletree.ProofOfAbsence && cc.useTBs:
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfAbsence:
	default:
		return protocol.ErrMalformedMessage
	}

	return cc.verifyAuthPath(profile, ap)
}

func (cc *ConsistencyChecks) verifyKeyLookup(profile *Profile,
	msg *protocol.Response) error {
	df := msg.DirectoryResponse.(*protocol.DirectoryProof)
	if len(df.AP) != 1 {
		return protocol.ErrMalformedMessage
	}

	ap := df.AP[0]
	proofType := ap.ProofType()
	switch {
	case msg.Error == protocol.ReqNameNotFound && proofType == merkletree.ProofOfAbsence:
	// FIXME: This would be changed when we support key changes
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfInclusion:
	case msg.Error == protocol.ReqSuccess && proofType == merkletree.ProofOfAbsence && cc.useTBs:
	default:
		return protocol.ErrMalformedMessage
	}

	return cc.verifyAuthPath(profile, ap)
}

func (cc *ConsistencyChecks) verifyAuthPath(profile *Profile,
	ap *merkletree.AuthenticationPath) error {
	str := cc.VerifiedSTR()
	// verify VRF Index
	vrfKey := str.Policies.VrfPublicKey
	if !vrfKey.Verify([]byte(profile.UserID), ap.LookupIndex, ap.VrfProof) {
		return protocol.CheckBadVRFProof
	}

	if profile.ProfileData == nil {
		// key is nil when the user does lookup for the first time.
		// Accept the received key as TOFU
		profile.ProfileData = ap.Leaf.Value
	}

	switch err := ap.Verify([]byte(profile.UserID), profile.ProfileData, str.TreeHash); err {
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

func (cc *ConsistencyChecks) updateTBs(profile *Profile,
	requestType int, msg *protocol.Response) error {
	if !cc.useTBs {
		return nil
	}

	df := msg.DirectoryResponse.(*protocol.DirectoryProof)
	ap := df.AP[0]
	switch requestType {
	case protocol.RegistrationType:
		if ap.ProofType() == merkletree.ProofOfAbsence {
			if err := cc.verifyReturnedPromise(profile, df); err != nil {
				return err
			}
		}
	case protocol.KeyLookupInEpochType:
		switch {
		case msg.Error == protocol.ReqSuccess &&
			ap.ProofType() == merkletree.ProofOfInclusion:
			if err := cc.verifyFulfilledPromise(profile, df); err != nil {
				return err
			}
			delete(cc.TBs, profile.UserID)
			return nil

		case msg.Error == protocol.ReqSuccess &&
			ap.ProofType() == merkletree.ProofOfAbsence:
			if err := cc.verifyReturnedPromise(profile, df); err != nil {
				return err
			}
		}
	}

	cc.TBs[profile.UserID] = df.TB
	profile.ProfileData = ap.Leaf.Value
	return nil
}

// verifyFulfilledPromise verifies issued TBs were inserted
// in the directory as promised.
func (cc *ConsistencyChecks) verifyFulfilledPromise(profile *Profile,
	df *protocol.DirectoryProof) error {
	ap := df.AP[0]
	// FIXME: Which epoch did this lookup happen in?
	if tb, ok := cc.TBs[profile.UserID]; ok {
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
func (cc *ConsistencyChecks) verifyReturnedPromise(profile *Profile,
	df *protocol.DirectoryProof) error {
	ap := df.AP[0]
	tb := df.TB
	str := cc.VerifiedSTR()

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
	if profile.ProfileData != nil &&
		!bytes.Equal(tb.Value, profile.ProfileData) {
		return protocol.CheckBindingsDiffer
	}
	return nil
}
