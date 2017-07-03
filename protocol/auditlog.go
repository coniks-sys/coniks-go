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
	dirName   string
	signKey   sign.PublicKey
	snapshots map[uint64]*DirSTR
	latestSTR *DirSTR
}

// A ConiksAuditLog maintains the histories
// of all CONIKS directories known to a CONIKS auditor,
// indexing the histories by the hash of a directory's initial
// STR.
// Each history includes the directory's domain name as a string, its
// public signing key enabling the auditor to verify the corresponding
// signed tree roots, and a list with all observed snapshots in
// chronological order.
type ConiksAuditLog struct {
	histories map[[crypto.HashSizeByte]byte]*directoryHistory
}

// computeInitSTRHash is a wrapper for the digest function;
// returns nil if the STR isn't an initial STR (i.e. str.Epoch != 0)
func computeInitSTRHash(initSTR *DirSTR) [crypto.HashSizeByte]byte {
	var initSTRHash [crypto.HashSizeByte]byte

	if initSTR.Epoch == 0 {
		// ugh HACK: need to call copy to convert slice into the array
		copy(initSTRHash[:], crypto.Digest(initSTR.Serialize()))
	}
	return initSTRHash
}

func newDirectoryHistory(dirName string, signKey sign.PublicKey, str *DirSTR) *directoryHistory {
	h := new(directoryHistory)
	h.dirName = dirName
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
	l.histories = make(map[[crypto.HashSizeByte]byte]*directoryHistory)
	return l
}

// IsKnownDirectory checks to see if an entry for the directory
// (indexed by the hash of its initial STR dirInitHash) exists
// in the audit log l. IsKnownDirectory() does not
// validate the entries themselves. It returns true if an entry exists,
// and false otherwise.
func (l *ConiksAuditLog) IsKnownDirectory(dirInitHash [crypto.HashSizeByte]byte) bool {
	h := l.histories[dirInitHash]
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

	// make sure we have oldEpochs unless we're inserting right
	// at the start of a directory's history
	if oldSTRs == nil && latestSTR.Epoch > 0 {
		return ErrMalformedDirectoryMessage
	}

	// compute the hash of the initial STR
	dirInitHash := computeInitSTRHash(latestSTR)
	if oldSTRs != nil {
		dirInitHash = computeInitSTRHash(oldSTRs[0])
	}

	// error if we want to create a new entry for a directory
	// we already know
	if l.IsKnownDirectory(dirInitHash) {
		return ErrAuditLog
	}

	// create the new directory history
	h := newDirectoryHistory(addr, signKey, latestSTR)

	startEp := uint64(0)
	endEp := latestSTR.Epoch

	// add each old STR into the history
	// This loop automatically catches if oldSTRs is malformed
	// (i.e. oldSTRs starts at epoch 0 and
	// len(oldSTRs) != latestSTR.Epoch-1)
	for ep := startEp; ep < endEp; ep++ {
		str := oldSTRs[ep]
		if str == nil {
			return ErrMalformedDirectoryMessage
		}
		h.snapshots[ep] = str
	}

	// don't forget to add the latest STR
	h.snapshots[endEp] = latestSTR
	l.histories[dirInitHash] = h

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
func (l *ConiksAuditLog) Update(dirInitHash [crypto.HashSizeByte]byte, newSTR *DirSTR) error {

	// error if we want to update the entry for an addr we don't know
	if !l.IsKnownDirectory(dirInitHash) {
		return ErrAuditLog
	}

	h := l.histories[dirInitHash]

	if err := verifySTRConsistency(h.signKey, h.latestSTR, newSTR); err != nil {
		return err
	}

	// update the latest STR
	h.snapshots[h.latestSTR.Epoch] = h.latestSTR
	h.latestSTR = newSTR
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
func (l *ConiksAuditLog) GetObservedSTRs(req *AuditingRequest) (*Response,
	ErrorCode) {

	// make sure we have a history for the requested directory in the log
	if !l.IsKnownDirectory(req.DirInitSTRHash) {
		return NewErrorResponse(ReqUnknownDirectory), ReqUnknownDirectory
	}

	h := l.histories[req.DirInitSTRHash]

	// make sure the request is well-formed
	if req.EndEpoch > h.latestSTR.Epoch || req.StartEpoch > req.EndEpoch {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	var strs []*DirSTR
	for ep := req.StartEpoch; ep < req.EndEpoch; ep++ {
		str := h.snapshots[ep]
		strs = append(strs, str)
	}

	// don't forget to append the STR for EndEpoch
	strs = append(strs, h.snapshots[req.EndEpoch])

	return NewSTRHistoryRange(strs)
}
