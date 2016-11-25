package client

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
)

// Config contains the client's configuration needed to send request to a
// CONIKS-server:
//  - the path to the server's VRF and signing public-key file, respectively;
//  - the actual public-keys parsed from these files.
type Config struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`
	VrfPubkeyPath  string `toml:"vrf_pubkey_path"`

	SigningPubKey sign.PublicKey
	VrfPubKey     vrf.PublicKey
}

// LoadConfig returns a client's configuration read from the given filename.
// It reads the (VRF and signing) public-key files and parses the actual keys.
// If there is any parsing or IO-error it returns and error (and the return
// config will be nil).
func LoadConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := utils.ResolvePath(conf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	// load VRF key
	vrfPath := utils.ResolvePath(conf.VrfPubkeyPath, file)
	vrfKey, err := ioutil.ReadFile(vrfPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read VRF key: %v", err)
	}
	if len(vrfKey) != vrf.PublicKeySize {
		return nil, fmt.Errorf("VRF public-key must be 32 bytes (got %d)", len(vrfKey))
	}
	conf.VrfPubKey = vrfKey
	conf.SigningPubKey = signPubKey

	return &conf, nil
}
