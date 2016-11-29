// Defines methods/functions to encode/decode messages between client
// and server. Currently this module supports JSON marshal/unmarshal only.
// Protobuf will be supported in the future.

package keyserver

import (
	"encoding/json"

	. "github.com/coniks-sys/coniks-go/protocol"
)

// MarshalResponse returns a JSON encoding of the server's response.
func MarshalResponse(response *Response) ([]byte, error) {
	return json.Marshal(response)
}

// UnmarshalRequest parses a JSON-encoded request msg and
// creates the corresponding protocol.Request, which will be handled
// by the server.
func UnmarshalRequest(msg []byte) (*Request, error) {
	var content json.RawMessage
	req := Request{
		Request: &content,
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil, err
	}
	var request interface{}
	switch req.Type {
	case RegistrationType:
		request = new(RegistrationRequest)
	case KeyLookupType:
		request = new(KeyLookupRequest)
	case KeyLookupInEpochType:
		request = new(KeyLookupInEpochRequest)
	case MonitoringType:
		request = new(MonitoringRequest)
	}
	if err := json.Unmarshal(content, &request); err != nil {
		return nil, err
	}
	req.Request = request
	return &req, nil
}
