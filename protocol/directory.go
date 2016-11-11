package protocol

import (
	"bytes"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

type ConiksDirectory struct {
	pad      *merkletree.PAD
	useTBs   bool
	tbs      map[string]*TemporaryBinding
	policies *merkletree.Policies
}

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

func (d *ConiksDirectory) Update() {
	d.pad.Update(d.policies)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
}

func (d *ConiksDirectory) SetPolicies(epDeadline merkletree.Timestamp, vrfKey vrf.PrivateKey) {
	d.policies = merkletree.NewPolicies(epDeadline, vrfKey)
}

func (d *ConiksDirectory) EpochDeadline() merkletree.Timestamp {
	return d.pad.LatestSTR().Policies.EpochDeadline
}

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
