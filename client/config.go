package client

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/utils"
)

// Config contains the client's configuration needed to send request to a
// CONIKS-server: the path to the server's signing public-key file
// and the actual public-key parsed from that file;
// a file path for storing the known bindings; and the server's addresses
// for sending registration requests and other types of request, respectively.
//
// Note that if RegAddress is empty, it will be fallback to use Address for
// all request types.
type Config struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`
	SigningPubKey  sign.PublicKey

	KeyStoragePath string `toml:"keys_storage_path"`

	RegAddress string `toml:"registration_address,omitempty"`
	Address    string `toml:"address"`
}

// LoadConfig returns a client's configuration read from the given filename.
// It reads the signing public-key file and parses the actual key.
// If there is any parsing or IO-error it returns an error (and the return
// config will be nil).
func LoadConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	conf.KeyStoragePath = utils.ResolvePath(conf.KeyStoragePath, file)

	// load signing key
	signPath := utils.ResolvePath(conf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	conf.SigningPubKey = signPubKey

	return &conf, nil
}
