package client

import (
	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/protocol"
)

// CreateRegistrationMsg returns a JSON encoding of
// a protocol.RegistrationRequest for the given (name, key) pair.
func CreateRegistrationMsg(name string, key []byte) ([]byte, error) {
	return application.MarshalRequest(protocol.RegistrationType,
		&protocol.RegistrationRequest{
			Username: name,
			Key:      key,
		})
}

// CreateKeyLookupMsg returns a JSON encoding of
// a protocol.KeyLookupRequest for the given name.
func CreateKeyLookupMsg(name string) ([]byte, error) {
	return application.MarshalRequest(protocol.KeyLookupType,
		&protocol.RegistrationRequest{
			Username: name,
		})
}
