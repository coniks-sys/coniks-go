package application

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/utils"
)

// ConfigLoader provides an interface for implementing
// different CONIKS application configuration encodings.
type ConfigLoader interface {
	Encode(conf AppConfig) error
	Decode(conf AppConfig) error
}

// newConfigLoader constructs a new ConfigLoader for the given encoding.
// If the encoding is unsupported, NewConfigLoader() returns a loader
// for the default encoding (TOML).
func newConfigLoader(encoding string) ConfigLoader {
	loader := configEncodings[encoding]
	if loader == nil {
		loader = new(TomlLoader)
	}
	return loader
}

// TomlLoader implements a ConfigLoader for toml-encoded CONIKS application
// configurations.
type TomlLoader struct{}

var _ ConfigLoader = (*TomlLoader)(nil)

// Encode saves the given configuration conf in toml encoding.
// If there is any encoding or IO error, Encode() returns an error.
func (ld *TomlLoader) Encode(conf AppConfig) error {
	var confBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	if err := e.Encode(conf); err != nil {
		return err
	}
	if err := utils.WriteFile(conf.GetPath(), confBuf.Bytes(), 0644); err != nil {
		return err
	}
	return nil
}

// Decode reads an application configuration from the given toml-encoded
// file. If there is any decoding error, Decode() returns an error.
func (ld *TomlLoader) Decode(conf AppConfig) error {
	if _, err := toml.DecodeFile(conf.GetPath(), conf); err != nil {
		return fmt.Errorf("Failed to load config: %v", err)
	}
	return nil
}

var configEncodings = map[string]ConfigLoader{
	"toml": new(TomlLoader),
}
