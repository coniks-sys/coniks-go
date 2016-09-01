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
	tbs      map[string]*merkletree.TemporaryBinding
	policies merkletree.Policies
}

type UpdatePolicies struct {
	EpDeadline merkletree.TimeStamp
	VrfKey     vrf.PrivateKey
}

func InitDirectory(epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey,
	signKey sign.PrivateKey, dirSize uint64, useTBs bool) *ConiksDirectory {
	d := new(ConiksDirectory)
	d.setPolicies(epDeadline, vrfKey)
	pad, err := merkletree.NewPAD(d.policies, signKey, dirSize)
	if err != nil {
		panic(err)
	}
	d.pad = pad
	d.useTBs = useTBs
	if useTBs {
		d.tbs = make(map[string]*merkletree.TemporaryBinding)
	}
	return d
}

func (d *ConiksDirectory) Update(up *UpdatePolicies) {
	d.pad.Update(d.policies)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
	if up != nil {
		d.setPolicies(up.EpDeadline, up.VrfKey)
	}
}

func (d *ConiksDirectory) setPolicies(epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey) {
	d.policies = merkletree.NewPolicies(epDeadline, vrfKey)
}

func (d *ConiksDirectory) EpochDeadline() merkletree.TimeStamp {
	return d.policies.EpDeadline()
}

func (d *ConiksDirectory) LatestSTR() *merkletree.SignedTreeRoot {
	return d.pad.LatestSTR()
}

// HandleOps validates the request message and then pass it to
// appropriate operation handler according to the request type.
func (d *ConiksDirectory) HandleOps(req *Request) (Response, ErrorCode) {
	switch req.Type {
	case RegistrationType:
		if msg, ok := req.Request.(*RegistrationRequest); ok {
			if len(msg.Username) > 0 && len(msg.Key) > 0 {
				return d.Register(msg)
			}
		}
	case KeyLookupType:
		if msg, ok := req.Request.(*KeyLookupRequest); ok {
			if len(msg.Username) > 0 {
				return d.KeyLookup(msg)
			}
		}
	case KeyLookupInEpochType:
		if msg, ok := req.Request.(*KeyLookupInEpochRequest); ok {
			if len(msg.Username) > 0 {
				return d.KeyLookupInEpoch(msg)
			}
		}
	case MonitoringType:
		if msg, ok := req.Request.(*MonitoringRequest); ok {
			if len(msg.Username) > 0 && msg.StartEpoch <= msg.EndEpoch {
				return d.Monitor(msg)
			}
		}
	}
	return NewErrorResponse(ErrorMalformedClientMessage),
		ErrorMalformedClientMessage
}

func (d *ConiksDirectory) Register(req *RegistrationRequest) (
	Response, ErrorCode) {
	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(ErrorDirectory), ErrorDirectory
	}
	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewRegistrationProof(ap, d.LatestSTR(), nil, ErrorNameExisted)
	}
	if d.useTBs {
		// also check the temporary bindings array
		// currently the server allows only one registration/key change per epoch
		if tb := d.tbs[req.Username]; tb != nil {
			return NewRegistrationProof(ap, d.LatestSTR(), tb, ErrorNameExisted)
		}

		// insert new data to the directory on-the-fly
		tb, err := d.pad.TB(req.Username, req.Key)
		if err != nil {
			return NewErrorResponse(ErrorDirectory), ErrorDirectory
		}
		d.tbs[req.Username] = tb
		return NewRegistrationProof(ap, d.LatestSTR(), tb, Success)
	} else {
		if err = d.pad.Set(req.Username, req.Key); err != nil {
			return NewErrorResponse(ErrorDirectory), ErrorDirectory
		}
		return NewRegistrationProof(ap, d.LatestSTR(), nil, Success)
	}
}

func (d *ConiksDirectory) KeyLookup(req *KeyLookupRequest) (
	Response, ErrorCode) {
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
	Response, ErrorCode) {
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
	Response, ErrorCode) {
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
