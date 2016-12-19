package client

import (
	"encoding/json"

	p "github.com/coniks-sys/coniks-go/protocol"
)

// UnmarshalResponse decodes the given message into a protocol.Response
// according to the given request type t. The request types are integer
// constants defined in the protocol package.
func UnmarshalResponse(t int, msg []byte) *p.Response {
	type Response struct {
		Error             p.ErrorCode
		DirectoryResponse json.RawMessage
	}
	var res Response
	if err := json.Unmarshal(msg, &res); err != nil {
		return &p.Response{
			Error: p.ErrMalformedDirectoryMessage,
		}
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in Errors
	if res.DirectoryResponse == nil {
		if !p.Errors[res.Error] {
			return &p.Response{
				Error: p.ErrMalformedDirectoryMessage,
			}
		}
		return &p.Response{
			Error: res.Error,
		}
	}

	switch t {
	case p.RegistrationType, p.KeyLookupType:
		response := new(p.DirectoryProof)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return &p.Response{
				Error: p.ErrMalformedDirectoryMessage,
			}
		}
		return &p.Response{
			Error:             res.Error,
			DirectoryResponse: response,
		}
	case p.KeyLookupInEpochType, p.MonitoringType:
		response := new(p.DirectoryProofs)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return &p.Response{
				Error: p.ErrMalformedDirectoryMessage,
			}
		}
		return &p.Response{
			Error:             res.Error,
			DirectoryResponse: response,
		}
	default:
		panic("Unknown request type")
	}
}

// CreateRegistrationMsg returns a JSON encoding of
// a protocol.RegistrationRequest for the given (name, key) pair.
func CreateRegistrationMsg(name string, key []byte) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.RegistrationType,
		Request: &p.RegistrationRequest{
			Username: name,
			Key:      key,
		},
	})
}

// CreateKeyLookupMsg returns a JSON encoding of
// a protocol.KeyLookupRequest for the given name.
func CreateKeyLookupMsg(name string) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.KeyLookupType,
		Request: &p.KeyLookupRequest{
			Username: name,
		},
	})
}
