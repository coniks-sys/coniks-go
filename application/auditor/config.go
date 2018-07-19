package auditor

import (
	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
)

// directoryConfig contains the auditor's configuration needed to send a
// request to a CONIKS server: the path to the server's signing public-key
// file and the actual public-key parsed from that file; the path to
// the server's initial STR file and the actual STR parsed from that file;
// the server's address for receiving STR history requests.
type directoryConfig struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`
	SigningPubKey  sign.PublicKey

	InitSTRPath string `toml:"init_str_path"`
	InitSTR     *protocol.DirSTR

	Address string `toml:"address"`
}

// Config maintains the auditor's configurations for all CONIKS
// directories it tracks.
type Config struct {
	TrackedDirs []*directoryConfig
	// TODO: Add server-side auditor config
}

var _ application.AppConfig = (*Config)(nil)

func newDirectoryConfig(signPubkeyPath, initSTRPath, serverAddr string) *directoryConfig {
	var dconf = directoryConfig{
		SignPubkeyPath: signPubkeyPath,
		InitSTRPath:    initSTRPath,
		Address:        serverAddr,
	}

	return &dconf
}

// NewConfig initializes a new auditor configuration with the given
// server signing public key path, registration address, and
// server address.
func NewConfig() *Config {
	var conf = Config{
		TrackedDirs: make([]*directoryConfig, 0),
	}
	return &conf
}

// AddDirectoryConfig adds the given CONIKS server settings to the
// auditor's configuration.
func (conf *Config) AddDirectoryConfig(signPubkeyPath, initSTRPath, serverAddr string) {
	dconf := newDirectoryConfig(signPubkeyPath, initSTRPath, serverAddr)
	conf.TrackedDirs = append(conf.TrackedDirs, dconf)
}

// Load initializes an auditor's configuration from the given file.
// For each directory in the configuration, it reads the signing public-key file
// and initial STR file, and parses the actual key and initial STR.
func (conf *Config) Load(file string) error {
	tmp, err := application.LoadConfig(file)
	if err != nil {
		return err
	}
	conf = tmp.(*Config)

	for _, dconf := range conf.TrackedDirs {
		// load signing key
		signPubKey, err := application.LoadSigningPubKey(dconf.SignPubkeyPath, file)
		if err != nil {
			return err
		}
		dconf.SigningPubKey = signPubKey

		// load initial STR
		initSTR, err := application.LoadInitSTR(dconf.InitSTRPath, file)
		if err != nil {
			return err
		}
		dconf.InitSTR = initSTR
	}

	return nil
}
