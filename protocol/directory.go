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

func InitDirectory(epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey,
	signKey sign.PrivateKey, dirSize uint64, useTBs bool) *ConiksDirectory {
	d := new(ConiksDirectory)
	d.SetPolicies(epDeadline, vrfKey)
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

func (d *ConiksDirectory) Update() {
	d.pad.Update(d.policies)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
}

func (d *ConiksDirectory) SetPolicies(epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey) {
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
				res, e := d.Register(msg)
				if res == nil {
					return NewErrorResponse(e), e
				}
				return res, e
			}
		}
	}
	return NewErrorResponse(ErrorMalformedClientMessage),
		ErrorMalformedClientMessage
}

func (d *ConiksDirectory) Register(req *RegistrationRequest) (
	*DirectoryProof, ErrorCode) {
	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return nil, ErrorDirectory
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
			return nil, ErrorDirectory
		}
		d.tbs[req.Username] = tb
		return NewRegistrationProof(ap, d.LatestSTR(), tb, Success)
	} else {
		if err = d.pad.Set(req.Username, req.Key); err != nil {
			return nil, ErrorDirectory
		}
		return NewRegistrationProof(ap, d.LatestSTR(), nil, Success)
	}
}
