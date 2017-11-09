package coniksauditor

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// DirectoryConfig contains the auditor's configuration needed to send a
// request to a CONIKS server: the path to the server's signing public-key
// file and the actual public-key parsed from that file; the path to
// the server's initial STR file and the actual STR parsed from that file;
// the server's address for receiving STR history requests.
type DirectoryConfig struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`
	SigningPubKey  sign.PublicKey

	InitSTRPath string `toml:"init_str_path"`
	InitSTR     *protocol.DirSTR

	Address string `toml:"address"`
}

// Config maintains the auditor's configurations for all CONIKS
// directories it tracks.
type Config []*DirectoryConfig

// LoadConfig returns a auditor's configuration read from the given filename.
// It reads the signing public-key file and parses the actual key, and
// the initial STR file and parses the actual STR.
// If there is any parsing or IO-error it returns an error (and the returned
// config will be nil).
func LoadConfig(file string) (*Config, error) {

	var conf Config
	// FIXME: Currently assuming there is only one tracked directory
	// Add a loop here to iterate over multiple directory
	// configs in the file
	var dirconf DirectoryConfig
	if _, err := toml.DecodeFile(file, &dirconf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := utils.ResolvePath(dirconf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	dirconf.SigningPubKey = signPubKey

	// load initial STR
	initSTRPath := utils.ResolvePath(dirconf.InitSTRPath, file)
	initSTRBytes, err := ioutil.ReadFile(initSTRPath)
	initSTR := new(protocol.DirSTR)
	if err := json.Unmarshal(initSTRBytes, &initSTR); err != nil {
		return nil, fmt.Errorf("Cannot parse initial STR: %v", err)
	}

	dirconf.InitSTR = initSTR

	conf = append(conf, &dirconf)

	return &conf, nil
}
