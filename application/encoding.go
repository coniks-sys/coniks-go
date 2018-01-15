// Defines methods/functions to encode/decode messages between client
// and server. Currently this module supports JSON marshal/unmarshal only.
// Protobuf will be supported in the future.

package application

import (
	"encoding/json"

	"github.com/coniks-sys/coniks-go/protocol"
)

// MarshalRequest returns a JSON encoding of the client's request.
func MarshalRequest(reqType int, request interface{}) ([]byte, error) {
	return json.Marshal(&protocol.Request{
		Type:    reqType,
		Request: request,
	})
}

// UnmarshalRequest parses a JSON-encoded request msg and
// creates the corresponding protocol.Request, which will be handled
// by the server.
func UnmarshalRequest(msg []byte) (*protocol.Request, error) {
	var content json.RawMessage
	req := protocol.Request{
		Request: &content,
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil, err
	}
	var request interface{}
	switch req.Type {
	case protocol.RegistrationType:
		request = new(protocol.RegistrationRequest)
	case protocol.KeyLookupType:
		request = new(protocol.KeyLookupRequest)
	case protocol.KeyLookupInEpochType:
		request = new(protocol.KeyLookupInEpochRequest)
	case protocol.MonitoringType:
		request = new(protocol.MonitoringRequest)
	}
	if err := json.Unmarshal(content, &request); err != nil {
		return nil, err
	}
	req.Request = request
	return &req, nil
}

// MarshalResponse returns a JSON encoding of the server's response.
func MarshalResponse(response *protocol.Response) ([]byte, error) {
	return json.Marshal(response)
}

// UnmarshalResponse decodes the given message into a protocol.Response
// according to the given request type t. The request types are integer
// constants defined in the protocol package.
func UnmarshalResponse(t int, msg []byte) *protocol.Response {
	type Response struct {
		Error             protocol.ErrorCode
		DirectoryResponse json.RawMessage
	}
	var res Response
	if err := json.Unmarshal(msg, &res); err != nil {
		return &protocol.Response{
			Error: protocol.ErrMalformedMessage,
		}
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in Errors
	if res.DirectoryResponse == nil {
		response := &protocol.Response{
			Error: res.Error,
		}
		err := response.Validate()
		return &protocol.Response{
			Error: err.(protocol.ErrorCode),
		}
	}

	switch t {
	case protocol.RegistrationType, protocol.KeyLookupType, protocol.KeyLookupInEpochType, protocol.MonitoringType:
		response := new(protocol.DirectoryProof)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return &protocol.Response{
				Error: protocol.ErrMalformedMessage,
			}
		}
		return &protocol.Response{
			Error:             res.Error,
			DirectoryResponse: response,
		}
	case protocol.STRType:
		response := new(protocol.STRHistoryRange)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return &protocol.Response{
				Error: protocol.ErrMalformedMessage,
			}
		}
		return &protocol.Response{
			Error:             res.Error,
			DirectoryResponse: response,
		}
	default:
		panic("Unknown request type")
	}
}

func malformedClientMsg(err error) *protocol.Response {
	// check if we're just propagating a message
	if err == nil {
		err = protocol.ErrMalformedMessage
	}
	return protocol.NewErrorResponse(protocol.ErrMalformedMessage)
}
