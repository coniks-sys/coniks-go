package server

import (
	"fmt"
	"io/ioutil"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// A Config contains configuration values
// which are read at initialization time from
// a TOML format configuration file.
type Config struct {
	*application.CommonConfig
	// LoadedHistoryLength is the maximum number of
	// snapshots kept in memory.
	LoadedHistoryLength uint64 `toml:"loaded_history_length"`
	// Policies contains the server's CONIKS policies configuration.
	Policies *Policies `toml:"policies"`
	// Addresses contains the server's connections configuration.
	Addresses []*Address `toml:"addresses"`
	// The server's epoch interval for updating the directory
	EpochDeadline protocol.Timestamp `toml:"epoch_deadline"`
}

var _ application.AppConfig = (*Config)(nil)

// NewConfig initializes a new server configuration at the given
// file path, with the given config encoding, server addresses, logger configuration,
// loaded history length and server application policies.
func NewConfig(file, encoding string, addrs []*Address,
	logConfig *application.LoggerConfig,
	loadedHistLen uint64, policies *Policies) *Config {
	var conf = Config{
		CommonConfig:        application.NewCommonConfig(file, encoding, logConfig),
		LoadedHistoryLength: loadedHistLen,
		Addresses:           addrs,
		Policies:            policies,
	}

	return &conf
}

// Load initializes a server configuration at the given file path
// using the given encoding.
// It reads the siging key pair and the VRF key
// pair into the Config instance and updates the path of
// TLS certificate files of each Address to absolute path.
func (conf *Config) Load(file, encoding string) error {
	conf.CommonConfig = application.NewCommonConfig(file, encoding, nil)
	if err := conf.GetLoader().Decode(conf); err != nil {
		return err
	}

	// load signing key
	signPath := utils.ResolvePath(conf.Policies.SignKeyPath, file)
	signKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signKey) != sign.PrivateKeySize {
		return fmt.Errorf("Signing key must be 64 bytes (got %d)", len(signKey))
	}

	// load VRF key
	vrfPath := utils.ResolvePath(conf.Policies.VRFKeyPath, file)
	vrfKey, err := ioutil.ReadFile(vrfPath)
	if err != nil {
		return fmt.Errorf("Cannot read VRF key: %v", err)
	}
	if len(vrfKey) != vrf.PrivateKeySize {
		return fmt.Errorf("VRF key must be 64 bytes (got %d)", len(vrfKey))
	}

	conf.Policies.vrfKey = vrfKey
	conf.Policies.signKey = signKey
	// also update path for TLS cert files
	for _, addr := range conf.Addresses {
		addr.TLSCertPath = utils.ResolvePath(addr.TLSCertPath, file)
		addr.TLSKeyPath = utils.ResolvePath(addr.TLSKeyPath, file)
	}
	// logger config
	conf.Logger.Path = utils.ResolvePath(conf.Logger.Path, file)

	return nil
}

// Save writes a server's configuration.
func (conf *Config) Save() error {
	return conf.GetLoader().Encode(conf)
}

// Path returns the server's configuration file path.
func (conf *Config) GetPath() string {
	return conf.Path
}
