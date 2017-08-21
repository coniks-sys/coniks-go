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

// insertRange inserts the given range of STRs snaps
// into the directoryHistory h.
// insertRange() assumes that snaps has been audited by Audit().
func (h *directoryHistory) insertRange(snaps []*DirSTR) {
	for i := 0; i < len(snaps); i++ {
		h.updateVerifiedSTR(snaps[i])
	}
}

// Audit checks that a directory's STR history
// is linear and updates the auditor's state
// if the checks pass.
// Audit() first checks the oldest STR in the
// STR range received in message against the h.verfiedSTR,
// and then verifies the remaining STRs in msg, and
// finally updates the snapshots if the checks pass.
// Audit() is called when an auditor receives new STRs
// from a specific directory.
func (h *directoryHistory) Audit(msg *Response) error {
	if err := msg.validate(); err != nil {
		return err.(ErrorCode)
	}

	strs := msg.DirectoryResponse.(*STRHistoryRange)

	// Since the str[0] is pinned in the audit log
	// expect that STR[0].Epoch is at least 1
	if strs.STR[0].Epoch < 1 {
		return ErrMalformedDirectoryMessage
	}

	// audit the STRs
	// if strs.STR is somehow malformed or invalid (e.g. strs.STR
	// contains old STRs), AuditDirectory() will detect this
	// and throw and error
	if err := h.AuditDirectory(strs.STR); err != CheckPassed {
		return err
	}

	// TODO: we should be storing inconsistent STRs nonetheless
	// so clients can detect inconsistencies -- or auditors
	// should blow the whistle and not store the bad STRs
	h.insertRange(strs.STR)

	return nil
}

// NewAuditLog constructs a new ConiksAuditLog. It creates an empty
// log; the auditor will add an entry for each CONIKS directory
// the first time it observes an STR for that directory.
func NewAuditLog() ConiksAuditLog {
	return make(map[[crypto.HashSizeByte]byte]*directoryHistory)
}

// set associates the given directoryHistory with the directory identifier
// (i.e. the hash of the initial STR) dirInitHash in the ConiksAuditLog.
func (l ConiksAuditLog) set(dirInitHash [crypto.HashSizeByte]byte,
	dirHistory *directoryHistory) {
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

// InitHistory creates a new directory history for the key directory addr
// and inserts it into the audit log l.
// The directory history is initialized with the key directory's
// signing key signKey, and a list of one or more snapshots snaps
// representing the pinned directory's STR history so far,
// in chronological order.
// InitHistory() returns an ErrAuditLog if the auditor attempts to create
// a new history for a known directory, and nil otherwise.
// InitHistory() is called by an auditor when it initializes its state
// from disk (either first-time startup, or after reboot).
func (l ConiksAuditLog) InitHistory(addr string, signKey sign.PublicKey,
	snaps []*DirSTR) error {

	// make sure we're getting an initial STR at the very least
	if len(snaps) < 1 || snaps[0].Epoch != 0 {
		// FIXME: This should be a more generic "malformed error"
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

	// TODO: re-verify all snaps although auditor should have
	// already done so in the past? After all, if we have
	// more than one snapshot, this means that the auditor is
	// re-initializing its state from disk, and it wouldn't have
	// saved those STRs if they didn't pass the Audit() checks.
	h.insertRange(snaps[1:])
	l.set(dirInitHash, h)

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
