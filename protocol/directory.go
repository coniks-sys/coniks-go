package protocol

import (
	"log"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/merkletree"
)

type ConiksUserPolicies struct {
	Username               string
	AllowUnsignedKeychange bool
	AllowPublicLookup      bool
}

type ConiksDirectory struct {
	*merkletree.PAD
}

func InitDirectory(policies merkletree.Policies, signKey sign.PrivateKey,
	dirSize uint64) *ConiksDirectory {
	pad, err := merkletree.NewPAD(policies, signKey, dirSize)
	if err != nil {
		panic(err)
	}
	return &ConiksDirectory{pad}
}

func (d *ConiksDirectory) Register(uname string, key []byte) (
	*merkletree.AuthenticationPath, *merkletree.TemporaryBinding, int) {
	// check whether the name already exists
	// in the directory before we register
	ap, err := d.Lookup(uname)
	if err != nil {
		return nil, nil, ErrorInternalServer
	}
	if ap.Leaf.Value() != nil {
		return ap, nil, ErrorNameExisted
	}

	// insert new data to the directory on-the-fly
	tb, err := d.TB(uname, key)
	if err != nil {
		log.Printf(err.Error())
		return nil, nil, ErrorInternalServer
	}
	return ap, tb, Success
}
