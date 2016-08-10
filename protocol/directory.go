package protocol

import (
	"bytes"
	"log"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

type ConiksUserPolicies struct {
	Username               string
	AllowUnsignedKeychange bool
	AllowPublicLookup      bool
}

type ConiksDirectory struct {
	pad      *merkletree.PAD
	useTBs   bool
	tbs      map[string]*merkletree.TemporaryBinding
	policies merkletree.Policies
}

func InitDirectory(epDeadline merkletree.TimeStamp, vrfKey *vrf.PrivateKey,
	signKey sign.PrivateKey, dirSize uint64,
	useTBs bool, capacity uint64) *ConiksDirectory {
	d := new(ConiksDirectory)
	d.policies = merkletree.NewPolicies(epDeadline, vrfKey)
	pad, err := merkletree.NewPAD(d.policies, signKey, dirSize)
	if err != nil {
		panic(err)
	}
	d.pad = pad
	d.useTBs = useTBs
	if useTBs {
		d.tbs = make(map[string]*merkletree.TemporaryBinding, capacity)
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

func (d *ConiksDirectory) SetPolicies(epDeadline merkletree.TimeStamp, vrfKey *vrf.PrivateKey) {
	d.policies = merkletree.NewPolicies(epDeadline, vrfKey)
}

func (d *ConiksDirectory) LatestSTR() *merkletree.SignedTreeRoot {
	return d.pad.LatestSTR()
}

func (d *ConiksDirectory) Register(uname string, key []byte) (
	*merkletree.AuthenticationPath, *merkletree.TemporaryBinding, ErrorCode) {
	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(uname)
	if err != nil {
		return nil, nil, ErrorInternalServer
	}
	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index()) {
		return ap, nil, ErrorNameExisted
	}
	if d.useTBs {
		// also check the temporary bindings array
		// currently the server allows only one registration/key change per epoch
		if d.tbs[uname] != nil {
			return nil, nil, ErrorNameExisted
		}

		// insert new data to the directory on-the-fly
		tb, err := d.pad.TB(uname, key)
		if err != nil {
			log.Printf(err.Error())
			return nil, nil, ErrorInternalServer
		}
		d.tbs[uname] = tb
		return ap, tb, Success
	}

	if err = d.pad.Set(uname, key); err != nil {
		log.Printf(err.Error())
		return nil, nil, ErrorInternalServer
	}

	return ap, nil, Success
}
