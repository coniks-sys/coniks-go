// This module implements a CONIKS audit log that a CONIKS auditor
// maintains.
// An audit log is a mirror of many CONIKS key directories' STR history,
// allowing CONIKS clients to audit the CONIKS directories.

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
	m "github.com/coniks-sys/coniks-go/merkletree"
)

type directoryHistory struct {
	auditState *auditorState
	snapshots map[uint64]*m.SignedTreeRoot
}

// A ConiksAuditLog maintains the histories
// of all CONIKS directories known to a CONIKS auditor.
// Each history includes the directory's public signing key
// enabling the auditor to verify the corresponding signed
// tree roots.
type ConiksAuditLog struct {
	histories map[string]*directoryHistory
}

func newDirectoryHistory(signKey sign.PublicKey, str *m.SignedTreeRoot) *directoryHistory {
	h := &directoryHistory{
		auditState: newAuditorState(signKey, str),
		snapshots: make(map[uint64]*m.SignedTreeRoot),
	}
	return h
}

// NewAuditLog constructs a new ConiksAuditLog. It creates an empty
// log; the auditor will add an entry for each CONIKS directory
// the first time it observes an STR for that directory.
func NewAuditLog() *ConiksAuditLog {
	l := &ConiksAuditLog{
		histories: make(map[string]*directoryHistory),
	}
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

// masomel: will probably want to write a more generic function
// for "catching up" on a history in case an auditor misses epochs
func (l *ConiksAuditLog) Insert(addr string, signKey sign.PublicKey,
	oldSTRs map[uint64]*m.SignedTreeRoot, latestSTR *m.SignedTreeRoot) error {

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

	return nil
}

// Update adds the newSTR into addr's directory history
// and returns nil if no error occurs, and an ErrAuditLog error
// otherwise. Update() assumes that Insert() has been called for
// addr prior to its first call and thereby expects that an entry for addr
// exists in the audit log l.
// Update() also assumes that auditor.verifySTRConsistency() has been
// called for newSTR and that this check has passed.
func (l *ConiksAuditLog) Update(addr string, newSTR *m.SignedTreeRoot) error {

	// panic if we want to update an entry for which we don't have
	if !l.IsKnownDirectory(addr) {
		return ErrAuditLog
	}

	h := l.histories[addr]

	// update the latest STR
	h.snapshots[h.latestSTR.Epoch] = h.auditState.latestSTR
	h.auditState.latestSTR = newSTR
	return nil
}

// Update adds the newSTR into addr's directory history
// and returns nil if no error occurs, and an ErrAuditLog error
// otherwise. Update() assumes that Insert() has been called for
// addr prior to its first call and thereby expects that an entry for addr
// exists in the audit log l.
// Update() also assumes that auditor.verifySTRConsistency() has been
// called for newSTR and that this check has passed.
func (l *ConiksAuditLog) UpdateRange(addr string, strs[] *m.SignedTreeRoot) error {

	// panic if we want to update an entry for which we don't have
	if !l.IsKnownDirectory(addr) {
		return ErrAuditLog
	}

	h := l.histories[addr]

	startEp := h.auditState.latestSTR.Epoch
	endEp := latestSTR.Epoch

	// add each old STR into the history
	for ep := startEp; ep < endEp; ep++ {
		str := oldSTRs[ep]
		if str == nil {
			return ErrMalformedDirectoryMessage
		}
		h.snapshots[ep] = str
	}

	// update the latest STR
	h.snapshots[h.latestSTR.Epoch] = h.auditState.latestSTR
	h.auditState.latestSTR = newSTR
	return nil
}

// GetObservedSTR gets the observed STR for the CONIKS directory address indicated
// in the AuditingRequest req received from a CONIKS client from the auditor's latest
// directory history entry, and returns a tuple of the form
// (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the auditor
// for logging purposes.
//
// A request without a directory address is considered
// malformed, and causes GetObservedSTR() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// GetObservedSTR() returns a message.NewObservedSTR(str) tuple.
// str is the signed tree root the auditor has observed for the latest epoch.
// If the auditor doesn't have any history entries for the requested CONIKS
// directory, GetObservedSTR() returns a
// message.NewErrorResponse(ReqUnknownDirectory) tuple.
func (l *ConiksAuditLog) GetObservedSTR(req *AuditingRequest) (*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.DirectoryAddr) <= 0 {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	if h := l.histories[req.DirectoryAddr]; h != nil {
		return NewObservedSTR(h.latestSTR)
	}

	return NewErrorResponse(ReqUnknownDirectory), ReqUnknownDirectory
}

// GetObservedSTRInEpoch gets the observed STR for the CONIKS directory address
// for a prior directory history entry indicated in the
// AuditingInEpochRequest req received from a CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the auditor
// for logging purposes.
//
// A request without a directory address or with an epoch greater than the latest
// observed epoch of this directory is considered malformed, and causes
// GetObservedSTRInEpoch() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// GetObservedSTRInEpoch() returns a message.NewObservedSTRs(strs) tuple.
// strs is a list of STRs for the epoch range [ep,
// l.histories[req.DirectoryAddr].latestSTR.Epoch], where ep is the past epoch
// for which the client has requested the observed STR.
// If the auditor doesn't have any history entries for the requested CONIKS
// directory, GetObservedSTR() returns a
// message.NewErrorResponse(ReqUnknownDirectory) tuple.
func (l *ConiksAuditLog) GetObservedSTRInEpoch(req *AuditingInEpochRequest) (*Response,
	ErrorCode) {

	// make sure the request is well-formed
	if len(req.DirectoryAddr) <= 0 {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	if h := l.histories[req.DirectoryAddr]; h != nil {

		// also make sure the epoch is well-formed
		if req.Epoch > h.latestSTR.Epoch {
			return NewErrorResponse(ErrMalformedClientMessage),
				ErrMalformedClientMessage
		}

		var strs []*m.SignedTreeRoot
		startEp := req.Epoch
		endEp := h.latestSTR.Epoch

		for ep := startEp; ep < endEp; ep++ {
			str := h.snapshots[ep]
			strs = append(strs, str)
		}

		// don't forget to append the latest STR
		strs = append(strs, h.latestSTR)

		return NewObservedSTRs(strs)
	}

	return NewErrorResponse(ReqUnknownDirectory), ReqUnknownDirectory
}
