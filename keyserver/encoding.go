// Defines methods/functions to encode/decode messages between client and server.
// Currently this module supports JSON marshal/unmarshal only.
// Protobuf would be supported in the feature.

package keyserver

import (
	"encoding/json"

	. "github.com/coniks-sys/coniks-go/protocol"
)

func MarshalResponse(response Response) ([]byte, error) {
	return json.Marshal(response)
}

func UnmarshalRequest(msg []byte) (*Request, error) {
	var content json.RawMessage
	req := Request{
		Request: &content,
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil, err
	}
	switch req.Type {
	case RegistrationType:
		var request RegistrationRequest
		if err := json.Unmarshal(content, &request); err != nil {
			return nil, err
		}
		req.Request = &request
	}
	return &req, nil
}
