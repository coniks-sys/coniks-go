package client

import (
	"encoding/json"

	p "github.com/coniks-sys/coniks-go/protocol"
)

// UnmarshalResponse decodes a JSON message from the CONKIS
// key server to the corresponding response based on
// the request type.
func UnmarshalResponse(t int, msg []byte) (
	*p.Response, p.ErrorCode) {
	type RawResponse struct {
		Error             p.ErrorCode
		DirectoryResponse json.RawMessage
	}
	var rawResponse RawResponse

	if err := json.Unmarshal(msg, &rawResponse); err != nil {
		return nil, p.ErrorMalformedDirectoryMessage
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in ErrorResponses
	if rawResponse.DirectoryResponse == nil {
		if !p.ErrorResponses[rawResponse.Error] {
			return nil, p.ErrorMalformedDirectoryMessage
		}
		return nil, rawResponse.Error
	}

	switch t {
	case p.RegistrationType, p.KeyLookupType:
		response := new(p.DirectoryProof)
		if err := json.Unmarshal(rawResponse.DirectoryResponse, &response); err != nil {
			return nil, p.ErrorMalformedDirectoryMessage
		}

		return &p.Response{Error: rawResponse.Error, DirectoryResponse: response},
			rawResponse.Error
	case p.KeyLookupInEpochType, p.MonitoringType:
		response := new(p.DirectoryProofs)
		if err := json.Unmarshal(rawResponse.DirectoryResponse, &response); err != nil {
			return nil, p.ErrorMalformedDirectoryMessage
		}
		return &p.Response{Error: rawResponse.Error, DirectoryResponse: response},
			rawResponse.Error
	}

	return nil, p.ErrorMalformedDirectoryMessage
}
