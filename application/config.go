package application

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/utils"
)

// AppConfig is the generic type used to specify the configuration of
// any kind of CONIKS application-level executable (e.g. key server,
// client etc.).
type AppConfig interface {
	Load(file string) error
	Save(file string) error
}

// ConfigService provides an abstraction of the underlying encoding format
// for the configs. It also contains some common configuration values including
// the logger configurations and the path of configuration file.
type ConfigService struct {
	app AppConfig

	Logger *LoggerConfig `toml:"logger"`
	Path   string
}

// NewConfigService initializes the ConfigService for the given app-specific
// config. This should be called in each method implementation of AppConfig.
func NewConfigService(conf AppConfig, path string) *ConfigService {
	return &ConfigService{
		app:  conf,
		Path: path,
	}
}

// Load reads an application configuration from the given toml-encoded
// file. If there is any decoding error, Load() returns an error
// with a nil config.
func (conf *ConfigService) Load() error {
	if _, err := toml.DecodeFile(conf.Path, conf.app); err != nil {
		return fmt.Errorf("Failed to load config: %v", err)
	}
	return nil
}

// Save stores the given configuration conf in the given
// file using toml encoding.
// If there is any encoding or IO error, Save() returns an error.
func (conf *ConfigService) Save() error {
	var confBuf bytes.Buffer
	e := toml.NewEncoder(&confBuf)
	if err := e.Encode(conf.app); err != nil {
		return err
	}
	return utils.WriteFile(conf.Path, confBuf.Bytes(), 0644)
}

// LoadSigningPubKey loads a public signing key at the given path
// specified in the given config file.
// If there is any parsing error or the key is malformed,
// LoadSigningPubKey() returns an error with a nil key.
func LoadSigningPubKey(path, file string) (sign.PublicKey, error) {
	signPath := utils.ResolvePath(path, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}
	return signPubKey, nil
}
