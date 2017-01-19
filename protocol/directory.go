// This module implements a CONIKS key directory that a CONIKS key server
// maintains.
// A directory is a publicly auditable, tamper-evident, privacy-preserving
// data structure that contains mappings from usernames to public keys.
// It currently supports registration, latest-version key lookups, past key
// lookups, and monitoring.
// It does not yet support key changes.

package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// A ConiksDirectory maintains the underlying persistent
// authenticated dictionary (PAD)
// and its policies (i.e. epoch deadline, VRF public key, etc.).
//
// The current implementation of ConiksDirectory also keeps track
// of temporary bindings (TBs). This feature may be split into a separate
// protocol extension in a future release.
type ConiksDirectory struct {
	pad      *merkletree.PAD
	useTBs   bool
	tbs      map[string]*TemporaryBinding
	policies *Policies
}

// NewDirectory constructs a new ConiksDirectory given the key server's PAD
// policies (i.e. epDeadline, vrfKey).
//
// signKey is the private key the key server uses to generate signed tree
// roots (STRs) and TBs.
// dirSize indicates the number of PAD snapshots the server keeps in memory.
// useTBs indicates whether the key server returns TBs upon a successful
// registration.
func NewDirectory(epDeadline Timestamp, vrfKey vrf.PrivateKey,
	signKey sign.PrivateKey, dirSize uint64, useTBs bool) *ConiksDirectory {
	// FIXME: see #110
	if !useTBs {
		panic("Currently the server is forced to use TBs")
	}
	d := new(ConiksDirectory)
	vrfPublicKey, ok := vrfKey.Public()
	if !ok {
		panic(vrf.ErrGetPubKey)
	}
	d.policies = NewPolicies(epDeadline, vrfPublicKey)
	pad, err := merkletree.NewPAD(d.policies, signKey, vrfKey, dirSize)
	if err != nil {
		panic(err)
	}
	d.pad = pad
	d.useTBs = useTBs
	if useTBs {
		d.tbs = make(map[string]*TemporaryBinding)
	}
	return d
}

// Update creates a new PAD snapshot updating this ConiksDirectory.
// Update() is called at the end of a CONIKS epoch. This implementation
// also deletes all issued TBs for the ending epoch as their
// corresponding mappings will have been inserted into the PAD.
func (d *ConiksDirectory) Update() {
	d.pad.Update(d.policies)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
}

// SetPolicies sets this ConiksDirectory's epoch deadline, which will be used
// in the next epoch.
func (d *ConiksDirectory) SetPolicies(epDeadline Timestamp) {
	d.policies = NewPolicies(epDeadline, d.policies.VrfPublicKey)
}

// EpochDeadline returns this ConiksDirectory's latest epoch deadline
// as a timestamp.
func (d *ConiksDirectory) EpochDeadline() Timestamp {
	return GetPolicies(d.pad.LatestSTR()).EpochDeadline
}

// LatestSTR returns this ConiksDirectory's latest STR.
func (d *ConiksDirectory) LatestSTR() *DirSTR {
	return NewDirSTR(d.pad.LatestSTR())
}

// NewTB creates a new temporary binding for the given name-to-key mapping.
// NewTB() computes the private index for the name, and
// digitally signs the (index, key, latest STR signature) tuple.
func (d *ConiksDirectory) NewTB(name string, key []byte) *TemporaryBinding {
	index := d.pad.Index(name)
	return &TemporaryBinding{
		Index:     index,
		Value:     key,
		Signature: d.pad.Sign(d.LatestSTR().Signature, index, key),
	}
}

// Register inserts the username-to-key mapping contained in a
// RegistrationRequest req received from a CONIKS client
// into this ConiksDirectory, and returns a tuple of the form
// (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username or without a public key is considered
// malformed, and causes Register() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// Register() inserts the new mapping in req
// into a pending version of the directory so it can be included in the
// snapshot taken at the end of the latest epoch, and returns a
// message.NewRegistrationProof(ap=proof of absence, str, tb, ReqSuccess)
// tuple if this operation succeeds.
// Otherwise, if the username already exists, Register() returns a
// message.NewRegistrationProof(ap=proof of inclusion, str, nil,
// ReqNameExisted) tuple. ap will be a proof of absence with a non-nil
// TB, if the username is still pending inclusion in the next directory
// snapshot.
// In any case, str is the signed tree root for the latest epoch.
// If Register() encounters an internal error at any point, it returns
// a message.NewErrorResponse(ErrDirectory) tuple.
func (d *ConiksDirectory) Register(req *RegistrationRequest) (
	*Response, ErrorCode) {
	// make sure the request is well-formed
	if len(req.Username) <= 0 || len(req.Key) <= 0 {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(ErrDirectory), ErrDirectory
	}
	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewRegistrationProof(ap, d.LatestSTR(), nil, ReqNameExisted)
	}

	var tb *TemporaryBinding

	if d.useTBs {
		// also check the temporary bindings array
		// currently the server allows only one registration/key change per epoch
		if tb = d.tbs[req.Username]; tb != nil {
			return NewRegistrationProof(ap, d.LatestSTR(), tb, ReqNameExisted)
		}
		tb = d.NewTB(req.Username, req.Key)
	}

	if err = d.pad.Set(req.Username, req.Key); err != nil {
		return NewErrorResponse(ErrDirectory), ErrDirectory
	}

	if tb != nil {
		d.tbs[req.Username] = tb
	}
	return NewRegistrationProof(ap, d.LatestSTR(), tb, ReqSuccess)
}

// KeyLookup gets the public key for the username indicated in the
// KeyLookupRequest req received from a CONIKS client from the latest
// snapshot of this ConiksDirectory, and returns a tuple of the form
// (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username is considered
// malformed, and causes KeyLookup() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// If the username doesn't have an entry in the latest directory
// snapshot and also isn't pending registration (i.e. has a corresponding
// TB), KeyLookup() returns a message.NewKeyLookupProof(ap=proof of absence,
// str, nil, ReqNameNotFound) tuple.
// Otherwise, KeyLookup() returns a message.NewKeyLookupProof(ap=proof of
// absence, str, tb, ReqSuccess) tuple if there is a corresponding TB for
// the username, but there isn't an entry in the directory yet, and a
// a message.NewKeyLookupProof(ap=proof of inclusion, str, nil, ReqSuccess)
// if there is.
// In any case, str is the signed tree root for the latest epoch.
// If KeyLookup() encounters an internal error at any point, it returns
// a message.NewErrorResponse(ErrDirectory) tuple.
func (d *ConiksDirectory) KeyLookup(req *KeyLookupRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(ErrDirectory), ErrDirectory
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupProof(ap, d.LatestSTR(), nil, ReqSuccess)
	}
	// if not found in the tree, do lookup in tb array
	if d.useTBs {
		if tb := d.tbs[req.Username]; tb != nil {
			return NewKeyLookupProof(ap, d.LatestSTR(), tb, ReqSuccess)
		}
	}
	return NewKeyLookupProof(ap, d.LatestSTR(), nil, ReqNameNotFound)
}

// KeyLookupInEpoch gets the public key for the username for a prior
// epoch in the directory history indicated in the
// KeyLookupInEpochRequest req received from a CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username or with an epoch greater than the latest
// epoch of this directory is considered malformed, and causes
// KeyLookupInEpoch() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// If the username doesn't have an entry in the directory
// snapshot for the indicated epoch, KeyLookupInEpoch()
// returns a message.NewKeyLookupInEpochProof(ap=proof of absence, str,
// ReqNameNotFound) tuple.
// Otherwise, KeyLookupInEpoch() returns a
// message.NewKeyLookupInEpochProof(ap=proof of inclusion, str, ReqSuccess)
// tuple.
// In either case, str is a list of STRs for the epoch range [ep,
// d.LatestSTR().Epoch], where ep is the past epoch for which
// the client has requested the user's key.
// KeyLookupInEpoch() proofs do not include temporary bindings since
// the TB corresponding to a registered binding is discarded at the time
// the binding is included in a directory snapshot.
// If KeyLookupInEpoch() encounters an internal error at any point,
// it returns a message.NewErrorResponse(ErrDirectory) tuple.
func (d *ConiksDirectory) KeyLookupInEpoch(req *KeyLookupInEpochRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.Epoch > d.LatestSTR().Epoch {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	var strs []*DirSTR
	startEp := req.Epoch
	endEp := d.LatestSTR().Epoch

	ap, err := d.pad.LookupInEpoch(req.Username, startEp)
	if err != nil {
		return NewErrorResponse(ErrDirectory), ErrDirectory
	}
	for ep := startEp; ep <= endEp; ep++ {
		str := NewDirSTR(d.pad.GetSTR(ep))
		strs = append(strs, str)
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupInEpochProof(ap, strs, ReqSuccess)
	}
	return NewKeyLookupInEpochProof(ap, strs, ReqNameNotFound)
}

// Monitor gets the directory proofs for the username for the range of
// epochs indicated in the MonitoringRequest req received from a
// CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username, with a start epoch greater than the
// latest epoch of this directory, or a start epoch greater than the
// end epoch is considered malformed, and causes Monitor() to return a
// message.NewErrorResponse(ErrMalformedClientMessage) tuple.
// Monitor() returns a message.NewMonitoringProof(ap, str) tuple.
// ap is a list of proofs of inclusion, and str is a list of STRs for
// the epoch range [startEpoch, endEpoch], where startEpoch
// and endEpoch are the epoch range endpoints indicated in the client's
// request. If req.endEpoch is greater than d.LatestSTR().Epoch,
// the end of the range will be set to d.LatestSTR().Epoch.
// If Monitor() encounters an internal error at any point,
// it returns a message.NewErrorResponse(ErrDirectory) tuple.
func (d *ConiksDirectory) Monitor(req *MonitoringRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.StartEpoch > d.LatestSTR().Epoch ||
		req.StartEpoch > req.EndEpoch {
		return NewErrorResponse(ErrMalformedClientMessage),
			ErrMalformedClientMessage
	}

	var strs []*DirSTR
	var aps []*merkletree.AuthenticationPath
	startEp := req.StartEpoch
	endEp := req.EndEpoch
	if endEp > d.LatestSTR().Epoch {
		endEp = d.LatestSTR().Epoch
	}
	for ep := startEp; ep <= endEp; ep++ {
		ap, err := d.pad.LookupInEpoch(req.Username, ep)
		if err != nil {
			return NewErrorResponse(ErrDirectory), ErrDirectory
		}
		aps = append(aps, ap)
		str := NewDirSTR(d.pad.GetSTR(ep))
		strs = append(strs, str)
	}

	return NewMonitoringProof(aps, strs)
}
