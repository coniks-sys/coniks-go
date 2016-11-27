package client

import (
	"encoding/json"

	"github.com/coniks-sys/coniks-go/merkletree"
	p "github.com/coniks-sys/coniks-go/protocol"
)

// UnmarshalResponse decodes the given message into a protocol.Response
// according to the given request-type t. This request-types are integer
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
		policies := &p.Policies{}
		if err := json.Unmarshal([]byte(response.STR.Ad.(merkletree.RawAd)), policies); err != nil {
			return &p.Response{
				Error: p.ErrMalformedDirectoryMessage,
			}
		}
		response.STR.Ad = policies
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
// a protocol.RegistrationRequest with the given (name, key) pair.
func CreateRegistrationMsg(name string, key []byte) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.RegistrationType,
		Request: &p.RegistrationRequest{
			Username: name,
			Key:      key,
		},
	})
}

// CreateLookupMsg returns a JSON encoding of
// a protocol.KeyLookupRequest with the given name.
func CreateLookupMsg(name string) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.KeyLookupType,
		Request: &p.KeyLookupRequest{
			Username: name,
		},
	})
}
