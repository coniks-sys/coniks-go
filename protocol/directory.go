// This module implements a CONIKS key directory that a CONIKS key server
// maintains.
// A directory is a publicly auditable, tamper-evident, privacy-preserving
// data structure that contains mappings from usernames to public keys.
// It currently supports registration, current key lookups, past key lookups,
// and monitoring.

package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// A CONIKS key directory maintains the underlying persistent
// authenticated dictionary (PAD)
// and its policies (i.e. epoch deadline, VRF public key, etc.).
//
// The current implementation of ConiksDirectory also keeps track
// of temporary bindings (TBs). This feature will be split into a separate
// protocol extension in a future release.
type ConiksDirectory struct {
	pad      *merkletree.PAD
	useTBs   bool
	tbs      map[string]*TemporaryBinding
	policies *merkletree.Policies
}

// Constructs a new ConiksDirectory given the key server's PAD
// policies (i.e. epDeadline, vrfKey).
//
// signKey is the private key the key server uses to sign signed tree
// roots (STRs) and TBs.
// dirSize indicates the number of PAD snapshots the server keeps in memory.
// useTBs indicates whether the key server returns TBs upon a successful
// registration.
func NewDirectory(epDeadline merkletree.Timestamp, vrfKey vrf.PrivateKey,
	signKey sign.PrivateKey, dirSize uint64, useTBs bool) *ConiksDirectory {

	// FIXME: see #110
	if !useTBs {
		panic("Currently the server is forced to use TBs")
	}

	d := new(ConiksDirectory)
	d.SetPolicies(epDeadline, vrfKey)
	pad, err := merkletree.NewPAD(d.policies, signKey, dirSize)
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

// Updates this ConiksDirectory, creating a new PAD snapshot. Update() is
//called at the end of a CONIKS epoch. This implementation also deletes all
// issued TBs for the ending epoch as their corresponding mappings
// will have been inserted into the PAD.
func (d *ConiksDirectory) Update() {
	d.pad.Update(d.policies)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
}

	// Sets this ConiksDirectory's epoch deadline and VRF private key.
func (d *ConiksDirectory) SetPolicies(epDeadline merkletree.Timestamp, vrfKey vrf.PrivateKey) {
	d.policies = merkletree.NewPolicies(epDeadline, vrfKey)
}

// Returns this ConiksDirectory's current epoch deadline as a timestamp.
func (d *ConiksDirectory) EpochDeadline() merkletree.Timestamp {
	return d.pad.LatestSTR().Policies.EpochDeadline
}

// Returns this ConiksDirectory's latest STR.
func (d *ConiksDirectory) LatestSTR() *merkletree.SignedTreeRoot {
	return d.pad.LatestSTR()
}

func (d *ConiksDirectory) NewTB(name string, key []byte) *TemporaryBinding {
	index := d.pad.Index(name)
	return &TemporaryBinding{
		Index:     index,
		Value:     key,
		Signature: d.pad.Sign(d.LatestSTR().Signature, index, key),
	}
}

// Registers the username-to-key mapping contained in a
// RegistrationRequest req received from a CONIKS client
// into this ConiksDirectory, and returns a tuple of the form
// (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username or without a public key is considered
// malformed, and causes Register() to return a (error response,
// ErrorMalformedClientMessage) tuple.
// If the given username already exists in the latest snapshot of the
// directory, Register() returns an (error response, ErrorNameExisted)
// tuple.
// Otherwise, Register() inserts the new mapping in req
// into the PAD so it can be included in the snapshot taken at the end
// of the current  epoch), and returns a (registration proof, Success)
// if this operation succeeds.
// If Register() encounters an internal error at any point, it returns
// an (error response, ErrorDirectory) tuple.
func (d *ConiksDirectory) Register(req *RegistrationRequest) (
	*Response, ErrorCode) {
	// make sure the request is well-formed
	if len(req.Username) <= 0 || len(req.Key) <= 0 {
		return NewErrorResponse(ErrorMalformedClientMessage),
			ErrorMalformedClientMessage
	}

	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(ErrorDirectory), ErrorDirectory
	}
	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewRegistrationProof(ap, d.LatestSTR(), nil, ErrorNameExisted)
	}

	var tb *TemporaryBinding

	if d.useTBs {
		// also check the temporary bindings array
		// currently the server allows only one registration/key change per epoch
		if tb = d.tbs[req.Username]; tb != nil {
			return NewRegistrationProof(ap, d.LatestSTR(), tb, ErrorNameExisted)
		}
		tb = d.NewTB(req.Username, req.Key)
	}

	if err = d.pad.Set(req.Username, req.Key); err != nil {
		return NewErrorResponse(ErrorDirectory), ErrorDirectory
	}

	if tb != nil {
		d.tbs[req.Username] = tb
	}
	return NewRegistrationProof(ap, d.LatestSTR(), tb, Success)
}

// Gets the public key for the username indicated in the KeyLookupRequest
// req received from a CONIKS client from the latest snapshot of
// this ConiksDirectory, and returns a tuple of the form
// (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username is considered
// malformed, and causes KeyLookup() to return a (error response,
// ErrorMalformedClientMessage) tuple.
// If the username doesn't have an entry in the directory and doesn't have a
// corresponding TB, KeyLookup() returns
// a (proof of absence, ErrorNameNotFound) tuple.
// Otherwise, KeyLookup() returns a (key lookup proof, Success) tuple.
// The proof will be a proof of absence including a TB, if there is a
// corresponding TB for the username,
// but there isn't an entry in the directory yet, and a proof of inclusion
// if there is an entry in the directory.
// If KeyLookup() encounters an internal error at any point, it returns
// an (error response, ErrorDirectory) tuple.
func (d *ConiksDirectory) KeyLookup(req *KeyLookupRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 {
		return NewErrorResponse(ErrorMalformedClientMessage),
			ErrorMalformedClientMessage
	}

	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(ErrorDirectory), ErrorDirectory
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupProof(ap, d.LatestSTR(), nil, Success)
	}
	// if not found in the tree, do lookup in tb array
	if d.useTBs {
		if tb := d.tbs[req.Username]; tb != nil {
			return NewKeyLookupProof(ap, d.LatestSTR(), tb, Success)
		}
	}
	return NewKeyLookupProof(ap, d.LatestSTR(), nil, ErrorNameNotFound)
}

// Gets the public key for the username for a prior epoch in the
// directory history indicated in the
// KeyLookupInEpochRequest req received from a CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username or with an epoch greater than the latest
// epoch of this directory is considered malformed, and causes KeyLookupInEpoch()
// to return a (error response, ErrorMalformedClientMessage) tuple.
// If the username doesn't have an entry in the directory,
// at the indicated snapshot, KeyLookupInEpoch() returns a (KeyLookupInEpoch
// proof of absence, ErrorNameNotFound) tuple.
// Otherwise, KeyLookupInEpoch() returns a (KeyLookupInEpoch proof of
// inclusion, Success) tuple.
// If KeyLookupInEpoch() encounters an internal error at any point,
// it returns an (error response, ErrorDirectory) tuple.
func (d *ConiksDirectory) KeyLookupInEpoch(req *KeyLookupInEpochRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.Epoch > d.LatestSTR().Epoch {
		return NewErrorResponse(ErrorMalformedClientMessage),
			ErrorMalformedClientMessage
	}

	var strs []*merkletree.SignedTreeRoot
	startEp := req.Epoch
	endEp := d.LatestSTR().Epoch

	ap, err := d.pad.LookupInEpoch(req.Username, startEp)
	if err != nil {
		return NewErrorResponse(ErrorDirectory), ErrorDirectory
	}
	for ep := startEp; ep <= endEp; ep++ {
		str := d.pad.GetSTR(ep)
		strs = append(strs, str)
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupInEpochProof(ap, strs, Success)
	}
	return NewKeyLookupInEpochProof(ap, strs, ErrorNameNotFound)
}

// Gets the directory proofs for the username for the range of
// epochs indicated in the MonitoringRequest req received from a
// CONIKS client,
// and returns a tuple of the form (response, error).
// The response (which also includes the error code) is supposed to
// be sent back to the client. The returned error is used by the key
// server for logging purposes.
//
// A request without a username, with a start epoch greater than the
// latest epoch of this directory, or a start epoch greater than the end epoch
// is considered malformed, and causes Monitor() to return a (error response,
// ErrorMalformedClientMessage) tuple.
// Monitor() returns a (monitoring proof, Success) tuple.
// If Monitor() encounters an internal error at any point,
// it returns an (error response, ErrorDirectory) tuple.
func (d *ConiksDirectory) Monitor(req *MonitoringRequest) (
	*Response, ErrorCode) {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.StartEpoch > d.LatestSTR().Epoch ||
		req.StartEpoch > req.EndEpoch {
		return NewErrorResponse(ErrorMalformedClientMessage),
			ErrorMalformedClientMessage
	}

	var strs []*merkletree.SignedTreeRoot
	var aps []*merkletree.AuthenticationPath
	startEp := req.StartEpoch
	endEp := req.EndEpoch
	if endEp > d.LatestSTR().Epoch {
		endEp = d.LatestSTR().Epoch
	}
	for ep := startEp; ep <= endEp; ep++ {
		ap, err := d.pad.LookupInEpoch(req.Username, ep)
		if err != nil {
			return NewErrorResponse(ErrorDirectory), ErrorDirectory
		}
		aps = append(aps, ap)
		str := d.pad.GetSTR(ep)
		strs = append(strs, str)
	}

	return NewMonitoringProof(aps, strs, Success)
}
