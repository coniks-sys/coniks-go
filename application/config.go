package application

import (
	"fmt"
	"io/ioutil"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// AppConfig provides an abstraction of the
// underlying encoding format for the configs.
type AppConfig interface {
	Load(file, encoding string) error
	Save() error
	GetPath() string
}

// CommonConfig is the generic type used to specify the configuration of
// any kind of CONIKS application-level executable (e.g. key server,
// client etc.). It contains some common configuration
// values including the file path, logger configuration, and config
// loader.
type CommonConfig struct {
	Path     string
	Logger   *LoggerConfig `toml:"logger"`
	Encoding string
	loader   ConfigLoader
}

// NewCommonConfig initializes an application's config file path,
// its loader for the given encoding, and the logger configuration.
// Note: This constructor must be called in each Load() method
// implementation of an AppConfig.
func NewCommonConfig(file, encoding string, logger *LoggerConfig) *CommonConfig {
	return &CommonConfig{
		Path:     file,
		Logger:   logger,
		Encoding: encoding,
		loader:   newConfigLoader(encoding),
	}
}

// GetLoader returns the config's loader.
func (conf *CommonConfig) GetLoader() ConfigLoader {
	return conf.loader
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

// LoadIinitSTR loads an initial STR at the given path
// specified in the given config file.
// If there is any parsing error or the STR is malformed,
// LoadInitSTR() returns an error with a nil STR.
func LoadInitSTR(path, file string) (*protocol.DirSTR, error) {
	initSTRPath := utils.ResolvePath(path, file)
	initSTRBytes, err := ioutil.ReadFile(initSTRPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read init STR: %v", err)
	}
	initSTR := new(protocol.DirSTR)
	if err := json.Unmarshal(initSTRBytes, &initSTR); err != nil {
		return nil, fmt.Errorf("Cannot parse initial STR: %v", err)
	}
	if initSTR.Epoch != 0 {
		return nil, fmt.Errorf("Initial STR epoch must be 0 (got %d)", initSTR.Epoch)
	}
	return initSTR, nil
}