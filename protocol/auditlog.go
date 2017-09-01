// This module implements a CONIKS audit log that a CONIKS auditor
// maintains.
// An audit log is a mirror of many CONIKS key directories' STR history,
// allowing CONIKS clients to audit the CONIKS directories.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type directoryHistory struct {
	*AudState
	addr      string
	snapshots map[uint64]*DirSTR
}

// caller validates that initSTR is for epoch 0.
func newDirectoryHistory(addr string, signKey sign.PublicKey, initSTR *DirSTR) *directoryHistory {
	a := NewAuditor(signKey, initSTR)
	h := &directoryHistory{
		AudState:  a,
		addr:      addr,
		snapshots: make(map[uint64]*DirSTR),
	}
	h.updateVerifiedSTR(initSTR)
	return h
}

// A ConiksAuditLog maintains the histories
// of all CONIKS directories known to a CONIKS auditor,
// indexing the histories by the hash of a directory's initial
// STR (specifically, the hash of the STR's signature).
// Each history includes the directory's domain addr as a string, its
// public signing key enabling the auditor to verify the corresponding
// signed tree roots, and a list with all observed snapshots in
// chronological order.
type ConiksAuditLog map[[crypto.HashSizeByte]byte]*directoryHistory

// updateVerifiedSTR inserts the latest verified STR into a directory history;
// assumes the STRs have been validated by the caller.
func (h *directoryHistory) updateVerifiedSTR(newVerified *DirSTR) {
	h.Update(newVerified)
	h.snapshots[newVerified.Epoch] = newVerified
}

// Audit checks that a directory's STR history
// is linear and updates the auditor's state
// if the checks pass.
// Audit() first checks the oldest STR in the
// STR range received in message against the h.verfiedSTR,
// and then verifies the remaining STRs in msg, and
// finally updates the snapshots if the checks pass.
// Audit() is called when an auditor receives new STRs
// from a directory.
func (h *directoryHistory) Audit(msg *Response) error {
	// TODO: Implement as part of the auditor-server protocol
	return CheckPassed
}

// NewAuditLog constructs a new ConiksAuditLog. It creates an empty
// log; the auditor will add an entry for each CONIKS directory
// the first time it observes an STR for that directory.
func NewAuditLog() ConiksAuditLog {
	return make(map[[crypto.HashSizeByte]byte]*directoryHistory)
}

// set associates the given directoryHistory with the directory identifier
// (i.e. the hash of the initial STR) dirInitHash in the ConiksAuditLog.
func (l ConiksAuditLog) set(dirInitHash [crypto.HashSizeByte]byte, dirHistory *directoryHistory) {
	l[dirInitHash] = dirHistory
}

// get retrieves the directory history for the given directory identifier
// dirInitHash from the ConiksAuditLog.
// Get() also returns a boolean indicating whether the requested dirInitHash
// is present in the log.
func (l ConiksAuditLog) get(dirInitHash [crypto.HashSizeByte]byte) (*directoryHistory, bool) {
	h, ok := l[dirInitHash]
	return h, ok
}

// Insert creates a new directory history for the key directory addr
// and inserts it into the audit log l.
// The directory history is initialized with the key directory's
// signing key signKey, and a list of snapshots snaps representing the
// directory's STR history so far, in chronological order.
// Insert() returns an ErrAuditLog if the auditor attempts to create
// a new history for a known directory, and nil otherwise.
// Insert() only creates the initial entry in the log for addr. Use Update()
// to insert newly observed STRs for addr in subsequent epochs.
// Insert() assumes that the caller
// has called Audit() on snaps before calling Insert().
// FIXME: pass Response message as param
// masomel: will probably want to write a more generic function
// for "catching up" on a history in case an auditor misses epochs
func (l ConiksAuditLog) Insert(addr string, signKey sign.PublicKey,
	snaps []*DirSTR) error {
	// make sure we're getting an initial STR at the very least
	if len(snaps) < 1 || snaps[0].Epoch != 0 {
		return ErrMalformedDirectoryMessage
	}

	// compute the hash of the initial STR
	dirInitHash := ComputeDirectoryIdentity(snaps[0])

	// error if we want to create a new entry for a directory
	// we already know
	h, ok := l.get(dirInitHash)
	if ok {
		return ErrAuditLog
	}

	// create the new directory history
	h = newDirectoryHistory(addr, signKey, snaps[0])

	// FIXME: remove this check --> caller calls Audit() before
	// this function
	// add each STR into the history
	// start at 1 since we've inserted the initial STR above
	// This loop automatically catches if snaps is malformed
	// (i.e. snaps is missing an epoch between 0 and the latest given)
	for i := 1; i < len(snaps); i++ {
		str := snaps[i]
		if str == nil {
			return ErrMalformedDirectoryMessage
		}

		// verify the consistency of each new STR before inserting
		// into the audit log
		if err := h.verifySTRConsistency(h.VerifiedSTR(), str); err != nil {
			return err
		}

		h.updateVerifiedSTR(snaps[i])
	}

	l.set(dirInitHash, h)

	return nil
}

// Update inserts a newly observed STR newSTR into the log entry for the
// directory history given by dirInitHash (hash of direcotry's initial STR).
// Update() assumes that Insert() has been called for
// dirInitHash prior to its first call and thereby expects that an
// entry for addr exists in the audit log l, and that the caller
// has called Audit() on newSTR before calling Update().
// Update() returns ErrAuditLog if the audit log doesn't contain an
// entry for dirInitHash.
// FIXME: pass Response message as param
func (l ConiksAuditLog) Update(dirInitHash [crypto.HashSizeByte]byte, newSTR *DirSTR) error {
	// error if we want to update the entry for an addr we don't know
	h, ok := l.get(dirInitHash)
	if !ok {
		return ErrAuditLog
	}

	// FIXME: remove this check --> caller calls Audit() before this
	// function
	if err := h.verifySTRConsistency(h.VerifiedSTR(), newSTR); err != nil {
		return err
	}

	// update the latest STR
	// FIXME: use STR slice from Response msg
	h.updateVerifiedSTR(newSTR)
	return nil
}

// GetObservedSTRs gets a range of observed STRs for the CONIKS directory
// address indicated in the AuditingRequest req received from a
// CONIKS client, and returns a tuple of the form (response, error).
// The response (which also includes the error code) is sent back to
// the client. The returned error is used by the auditor
// for logging purposes.
//
// A request without a directory address, with a StartEpoch or EndEpoch
// greater than the latest observed epoch of this directory, or with
// at StartEpoch > EndEpoch is considered
// malformed and causes GetObservedSTRs() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// GetObservedSTRs() returns a message.NewSTRHistoryRange(strs) tuple.
// strs is a list of STRs for the epoch range [StartEpoch, EndEpoch];
// if StartEpoch == EndEpoch, the list returned is of length 1.
// If the auditor doesn't have any history entries for the requested CONIKS
// directory, GetObservedSTRs() returns a
// message.NewErrorResponse(ReqUnknownDirectory) tuple.
func (l ConiksAuditLog) GetObservedSTRs(req *AuditingRequest) (*Response,
	ErrorCode) {
	// make sure we have a history for the requested directory in the log
	h, ok := l.get(req.DirInitSTRHash)
	if !ok {
		return NewErrorResponse(ReqUnknownDirectory), ReqUnknownDirectory
	}

	// make sure the request is well-formed
	if req.EndEpoch > h.VerifiedSTR().Epoch || req.StartEpoch > req.EndEpoch {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	var strs []*DirSTR
	for ep := req.StartEpoch; ep <= req.EndEpoch; ep++ {
		str := h.snapshots[ep]
		strs = append(strs, str)
	}

	return NewSTRHistoryRange(strs)
}
