// This module implements a CONIKS audit log that a CONIKS auditor
// maintains.
// An audit log is a mirror of many CONIKS key directories' STR history,
// allowing CONIKS clients to audit the CONIKS directories.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type directoryHistory struct {
	addr      string
	signKey   sign.PublicKey
	snapshots map[uint64]*DirSTR
	latestSTR *DirSTR
}

// A ConiksAuditLog maintains the histories
// of all CONIKS directories known to a CONIKS auditor,
// indexing the histories by the hash of a directory's initial
// STR (specifically, the hash of the STR's signature as a string).
// Each history includes the directory's domain addr as a string, its
// public signing key enabling the auditor to verify the corresponding
// signed tree roots, and a list with all observed snapshots in
// chronological order.
type ConiksAuditLog map[[crypto.HashSizeByte]byte]*directoryHistory

// updateLatestSTR inserts a new STR into a directory history;
// assumes the STR has been validated by the caller
func (h *directoryHistory) updateLatestSTR(newLatest *DirSTR) {
	h.snapshots[newLatest.Epoch] = newLatest
	h.latestSTR = newLatest
}

// caller validates that initSTR is for epoch 0
func newDirectoryHistory(addr string, signKey sign.PublicKey, initSTR *DirSTR) *directoryHistory {
	h := new(directoryHistory)
	h.addr = addr
	h.signKey = signKey
	h.snapshots = make(map[uint64]*DirSTR)
	h.latestSTR = nil
	return h
}

// NewAuditLog constructs a new ConiksAuditLog. It creates an empty
// log; the auditor will add an entry for each CONIKS directory
// the first time it observes an STR for that directory.
func NewAuditLog() ConiksAuditLog {
	return make(map[[crypto.HashSizeByte]byte]*directoryHistory)
}

// set associates the given directoryHistory with the directory identifier
// (i.e. the hash of the initial STR) dirInitHash in the ConiksAuditLog.
func (l ConiksAuditLog) set(dirInitHash string, dirHistory *directoryHistory) {
	l[dirInitHash] = dirHistory
}

// get retrieves the directory history for the given directory identifier
// dirInitHash from the ConiksAuditLog.
// Get() also returns a boolean indicating whether the requested dirInitHash
// is present in the log.
func (l ConiksAuditLog) get(dirInitHash string) (*directoryHistory, bool) {
	h, ok := l[dirInitHash]
	return h, ok
}

// updateLatestSTR inserts a new STR into a directory history;
// assumes the STR has been validated by the caller
func (h *directoryHistory) updateLatestSTR(newLatest *DirSTR) {
	h.snapshots[newLatest.Epoch] = newLatest
	h.latestSTR = newLatest
}

// Insert creates a new directory history for the key directory addr
// and inserts it into the audit log l.
// The directory history is initialized with the key directory's
// signing key signKey, and a list of snapshots snaps representing the
// directory's STR history so far, in chronological order.
// Insert() returns an ErrAuditLog if the auditor attempts to create
// a new history for a known directory, an ErrMalformedDirectoryMessage
// if oldSTRs is malformed, and nil otherwise.
// Insert() only creates the initial entry in the log for addr. Use Update()
// to insert newly observed STRs for addr in subsequent epochs.
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

	// add each STR into the history
	// start at 1 since we've inserted the initial STR above
	// This loop automatically catches if snaps is malformed
	// (i.e. snaps is missing an epoch between 0 and the latest given)
	for i := 1; i < len(snaps); i++ {
		str := snaps[i]
		if str == nil || str.Epoch != uint64(i) {
			return ErrMalformedDirectoryMessage
		}

		// verify the consistency of each new STR before inserting
		// into the audit log
		if err := verifySTRConsistency(signKey, h.latestSTR, str); err != nil {
			return err
		}

		h.updateLatestSTR(snaps[i])
	}

	// Finally, add the new history to the log
	l.set(dirInitHash, h)

	return nil
}

// Update verifies the consistency of a newly observed STR newSTR for
// the directory addr, and inserts the newSTR into addr's directory history
// if the checks (i.e. STR signature and hash chain verifications) pass.
// Update() returns nil if the checks pass, and the appropriate consistency
// check error otherwise. Update() assumes that Insert() has been called for
// addr prior to its first call and thereby expects that an entry for addr
// exists in the audit log l.
// FIXME: pass Response message as param
func (l ConiksAuditLog) Update(dirInitHash [crypto.HashSizeByte]byte, newSTR *DirSTR) error {

	// error if we want to update the entry for an addr we don't know
	h, ok := l.get(dirInitHash)
	if !ok {
		return ErrAuditLog
	}

	if err := verifySTRConsistency(h.signKey, h.latestSTR, newSTR); err != nil {
		return err
	}

	// update the latest STR
	h.updateLatestSTR(newSTR)
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
	if req.EndEpoch > h.latestSTR.Epoch || req.StartEpoch > req.EndEpoch {
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
