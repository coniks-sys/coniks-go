package client

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
	"io/ioutil"
)

type Config struct {
	configPath string

	SignPubkeyPath string `toml:"sign_pubkey_path"`
	VrfPubkeyPath  string `toml:"vrf_pubkey_path"`

	SigningPubKey sign.PublicKey
	VrfPubKey     vrf.PublicKey
}

func LoadConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := util.ResolvePath(conf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	// load VRF key
	vrfPath := util.ResolvePath(conf.VrfPubkeyPath, file)
	vrfKey, err := ioutil.ReadFile(vrfPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read VRF key: %v", err)
	}
	if len(vrfKey) != vrf.PublicKeySize {
		return nil, fmt.Errorf("VRF public-key must be 32 bytes (got %d)", len(vrfKey))
	}
	conf.configPath = file
	conf.VrfPubKey = vrfKey
	conf.SigningPubKey = signPubKey

	return &conf, nil
}
