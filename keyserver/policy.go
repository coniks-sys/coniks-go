package keyserver

import (
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
)

type ServerPolicies struct {
	EpochDeadline merkletree.TimeStamp `toml:"epoch_deadline"`
	VRFKeyPath    string               `toml:"vrf_key_path"`
	VRFKey        *vrf.PrivateKey
}

func readPolicies(path string) (*ServerPolicies, error) {
	var p ServerPolicies
	if _, err := toml.DecodeFile(path, &p); err != nil {
		log.Fatalf("Failed to load config: %v", err)
		return nil, err
	}

	// load vrf key
	skBytes, err := ioutil.ReadFile(p.VRFKeyPath)
	if err != nil {
		log.Fatalf("Cannot read VRF key: %v", err)
		return nil, nil
	}
	if len(skBytes) != vrf.PrivateKeySize {
		log.Fatalf("Signing key must be 64 bytes (got %d)", len(skBytes))
		return nil, nil
	}
	p.VRFKey = new(vrf.PrivateKey)
	copy(p.VRFKey[:], skBytes)

	return &p, nil
}
