package client

import (
	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/crypto/sign"
)

// Config contains the client's configuration needed to send a request to a
// CONIKS server: the path to the server's signing public-key file
// and the actual public-key parsed from that file; the server's addresses
// for sending registration requests and other types of requests,
// respectively.
//
// Note that if RegAddress is empty, the client falls back to using Address
// for all request types.
type Config struct {
	*application.ConfigService

	SignPubkeyPath string `toml:"sign_pubkey_path"`

	SigningPubKey sign.PublicKey

	RegAddress string `toml:"registration_address,omitempty"`
	Address    string `toml:"address"`
}

var _ application.AppConfig = (*Config)(nil)

// NewConfig initializes a new client configuration with the given
// server signing public key path, registration address, and
// server address.
func NewConfig(signPubkeyPath, regAddr, serverAddr string) *Config {
	var conf = Config{
		SignPubkeyPath: signPubkeyPath,
		RegAddress:     regAddr,
		Address:        serverAddr,
	}

	return &conf
}

// Load initializes a client's configuration from the given file.
// It reads the signing public-key file and parses the actual key.
func (conf *Config) Load(file string) error {
	conf.ConfigService = application.NewConfigService(conf)
	if err := conf.ConfigService.Load(file); err != nil {
		return err
	}

	// load signing key
	signPubKey, err := application.LoadSigningPubKey(conf.SignPubkeyPath, file)
	if err != nil {
		return err
	}
	conf.SigningPubKey = signPubKey

	return nil
}

// Save writes a client's configuration to the given config file.
func (conf *Config) Save(file string) error {
	conf.ConfigService = application.NewConfigService(conf)
	return conf.ConfigService.Save(file)
}
