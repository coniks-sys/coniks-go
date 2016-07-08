package protocol

import (
	"log"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

type ConiksDirectory struct {
	pad *merkletree.PAD
}

func InitDirectory(policies merkletree.Policies, secretKey crypto.SigningKey,
	dirSize uint64) *ConiksDirectory {
	pad, err := merkletree.NewPAD(policies, secretKey, dirSize)
	if err != nil {
		panic(err)
	}
	d := new(ConiksDirectory)
	d.pad = pad
	return d
}

func (d *ConiksDirectory) Update(policies merkletree.Policies) {
	d.pad.Update(policies)
}

func (d *ConiksDirectory) LatestSTR() *merkletree.SignedTreeRoot {
	return d.pad.LatestSTR()
}

func (d *ConiksDirectory) Register(uname string, key []byte) (
	*merkletree.AuthenticationPath, *merkletree.TemporaryBinding, int) {
	// check whether the name already exists
	// in the directory before we register
	ap, err := d.pad.Lookup(uname)
	if err != nil {
		return nil, nil, ErrorInternalServer
	}
	if ap.Leaf.Value() != nil {
		return ap, nil, ErrorNameExisted
	}

	// insert new data to the directory on-the-fly
	tb, err := d.pad.TB(uname, key)
	if err != nil {
		log.Printf(err.Error())
		return nil, nil, ErrorInternalServer
	}
	return ap, tb, Success
}
