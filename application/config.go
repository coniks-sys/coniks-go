package application

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// AppConfig is the generic type used to specify the configuration of
// any kind of CONIKS application-level executable (e.g. key server,
// client etc.).
type AppConfig interface {
	Load(file string) error
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

// LoadConfig loads an application configuration from the given toml-encoded
// file. If there is any decoding error, an LoadConfig() returns an error
// with a nil config.
func LoadConfig(file string) (AppConfig, error) {
	var conf AppConfig
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}
	return conf, nil
}

// SaveConfig stores the given configuration conf in the given
// file using toml encoding.
// If there is any encoding or IO error, SaveConfig() returns an error.
func SaveConfig(file string, conf AppConfig) error {
	var confBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	if err := e.Encode(conf); err != nil {
		return err
	}
	if err := utils.WriteFile(file, confBuf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}
