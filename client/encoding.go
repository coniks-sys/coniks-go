package client

import (
	"encoding/json"

	p "github.com/coniks-sys/coniks-go/protocol"
)

func UnmarshalResponse(t int, msg []byte) (
	p.DirectoryResponse, p.ErrorCode) {
	type Response struct {
		Error             p.ErrorCode
		DirectoryResponse json.RawMessage
	}
	var res Response
	if err := json.Unmarshal(msg, &res); err != nil {
		return nil, p.ErrorMalformedDirectoryMessage
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in ErrorResponses
	if res.DirectoryResponse == nil {
		if !p.ErrorResponses[res.Error] {
			return nil, p.ErrorMalformedDirectoryMessage
		} else {
			return nil, res.Error
		}
	}

	switch t {
	case p.RegistrationType, p.KeyLookupType:
		response := new(p.DirectoryProof)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return nil, p.ErrorMalformedDirectoryMessage
		}
		return response, res.Error
	case p.KeyLookupInEpochType, p.MonitoringType:
		response := new(p.DirectoryProofs)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return nil, p.ErrorMalformedDirectoryMessage
		}
		return response, res.Error
	}
	return nil, p.ErrorMalformedDirectoryMessage
}
