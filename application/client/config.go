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
	*application.CommonConfig

	SignPubkeyPath string `toml:"sign_pubkey_path"`

	SigningPubKey sign.PublicKey

	RegAddress string `toml:"registration_address,omitempty"`
	Address    string `toml:"address"`
}

var _ application.AppConfig = (*Config)(nil)

// NewConfig initializes a new client configuration at the
// given file path, with the given config encoding,
// server signing public key path, registration address, and
// server address.
func NewConfig(file, encoding string, signPubkeyPath, regAddr,
	serverAddr string) *Config {
	var conf = Config{
		CommonConfig:   application.NewCommonConfig(file, encoding, nil),
		SignPubkeyPath: signPubkeyPath,
		RegAddress:     regAddr,
		Address:        serverAddr,
	}

	return &conf
}

// Load initializes a client's configuration from the given file
// using the given encoding.
// It reads the signing public-key file and parses the actual key.
func (conf *Config) Load(file, encoding string) error {
	conf.CommonConfig = application.NewCommonConfig(file, encoding, nil)
	if err := conf.GetLoader().Decode(conf); err != nil {
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

// Save writes a client's configuration.
func (conf *Config) Save() error {
	return conf.GetLoader().Encode(conf)
}

// Path returns the client's configuration file path.
func (conf *Config) GetPath() string {
	return conf.Path
}
