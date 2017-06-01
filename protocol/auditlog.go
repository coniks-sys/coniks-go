// This module implements a CONIKS audit log that a CONIKS auditor
// maintains.
// An audit log is a mirror of many CONIKS key directories' STR history,
// allowing CONIKS clients to audit the CONIKS directories.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

type directoryHistory struct {
	signKey   sign.PublicKey
	snapshots map[uint64]*DirSTR
	latestSTR *DirSTR
}

// A ConiksAuditLog maintains the histories
// of all CONIKS directories known to a CONIKS auditor.
// Each history includes the directory's public signing key
// enabling the auditor to verify the corresponding signed
// tree roots.
type ConiksAuditLog struct {
	histories map[string]*directoryHistory
}

func newDirectoryHistory(signKey sign.PublicKey, str *DirSTR) *directoryHistory {
	h := new(directoryHistory)
	h.signKey = signKey
	h.snapshots = make(map[uint64]*DirSTR)
	h.latestSTR = str
	return h
}

// NewAuditLog constructs a new ConiksAuditLog. It creates an empty
// log; the auditor will add an entry for each CONIKS directory
// the first time it observes an STR for that directory.
func NewAuditLog() *ConiksAuditLog {
	l := new(ConiksAuditLog)
	l.histories = make(map[string]*directoryHistory)
	return l
}

// IsKnownDirectory checks to see if an entry for the directory
// address addr exists in the audit log l. IsKnownDirectory() does not
// validate the entries themselves. It returns true if an entry exists,
// and false otherwise.
func (l *ConiksAuditLog) IsKnownDirectory(addr string) bool {
	h := l.histories[addr]
	if h != nil {
		return true
	}
	return false
}

// Insert creates a new directory history for the key directory addr
// and inserts it into the audit log l.
// The directory history is initialized with the key directory's
// signing key signKey, a list of STRs representing the
// directory's prior history oldSTRs, and the directory's latest STR
// latestSTR.
// Insert() returns an ErrAuditLog if the auditor attempts to create
// a new history for a known directory, an ErrMalformedDirectoryMessage
// if oldSTRs is malformed, and nil otherwise.
// Insert() only creates the initial entry in the log for addr. Use Update()
// to insert newly observed STRs for addr in subsequent epochs.
// FIXME: pass Response message as param
// masomel: will probably want to write a more generic function
// for "catching up" on a history in case an auditor misses epochs
func (l *ConiksAuditLog) Insert(addr string, signKey sign.PublicKey,
	oldSTRs map[uint64]*DirSTR, latestSTR *DirSTR) error {

	// error if we want to create a new entry for an addr we already know
	if l.IsKnownDirectory(addr) {
		return ErrAuditLog
	}

	// create the new directory history
	h := newDirectoryHistory(signKey, latestSTR)

	startEp := uint64(0)
	endEp := latestSTR.Epoch

	// add each old STR into the history
	for ep := startEp; ep < endEp; ep++ {
		str := oldSTRs[ep]
		if str == nil {
			return ErrMalformedDirectoryMessage
		}
		h.snapshots[ep] = str
	}

	l.histories[addr] = h

	// FIXME: verify the consistency of each new STR
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
func (l *ConiksAuditLog) Update(addr string, newSTR *DirSTR) error {

	// error if we want to update the entry for an addr we don't know
	if !l.IsKnownDirectory(addr) {
		return ErrAuditLog
	}

	h := l.histories[addr]

	if err := verifySTRConsistency(h.signKey, h.latestSTR, newSTR); err != nil {
		return err
	}

	// update the latest STR
	h.snapshots[h.latestSTR.Epoch] = h.latestSTR
	h.latestSTR = newSTR
	return nil
}

// GetObservedSTRs gets the observed STR for the CONIKS directory
// address for a directory history entry indicated in the
// AuditingRequest req received from a CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the auditor
// for logging purposes.
//
// A request without a directory address or with an epoch greater than
// the latest observed epoch of this directory is considered malformed,
// and causes GetObservedSTRs() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// GetObservedSTRs() returns a message.NewSTRHistoryRange(strs) tuple.
// strs is a list of STRs for the epoch range [ep,
// l.histories[req.DirectoryAddr].latestSTR.Epoch], where ep is the epoch for
// which the client has requested the observed STR; i.e. if ep == the latest epoch,
// the list returned is of length 1.
// If the auditor doesn't have any history entries for the requested CONIKS
// directory, GetObservedSTRs() returns a
// message.NewErrorResponse(ReqUnknownDirectory) tuple.
func (l *ConiksAuditLog) GetObservedSTRs(req *AuditingRequest) (*Response,
	ErrorCode) {

	// make sure the request is well-formed
	if len(req.DirectoryAddr) <= 0 {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	h := l.histories[req.DirectoryAddr]

	if h == nil {
		return NewErrorResponse(ReqUnknownDirectory), ReqUnknownDirectory
	}

	// also make sure the epoch is well-formed
	if req.Epoch > h.latestSTR.Epoch {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	var strs []*DirSTR
	startEp := req.Epoch
	endEp := h.latestSTR.Epoch

	for ep := startEp; ep < endEp; ep++ {
		str := h.snapshots[ep]
		strs = append(strs, str)
	}

	// don't forget to append the latest STR
	strs = append(strs, h.latestSTR)

	return NewSTRHistoryRange(strs)
}
