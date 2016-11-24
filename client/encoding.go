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
		// FIXME: fmt.Println(err) yields:
		// json: cannot unmarshal object into Go value of type merkletree.AssocData
		return nil, p.ErrMalformedDirectoryMessage
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in Errors
	if res.DirectoryResponse == nil {
		if !p.Errors[res.Error] {
			return nil, p.ErrMalformedDirectoryMessage
		} else {
			return nil, res.Error
		}
	}

	switch t {
	case p.RegistrationType, p.KeyLookupType:
		response := new(p.DirectoryProof)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return nil, p.ErrMalformedDirectoryMessage
		}
		return response, res.Error
	case p.KeyLookupInEpochType, p.MonitoringType:
		response := new(p.DirectoryProofs)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			return nil, p.ErrMalformedDirectoryMessage
		}
		return response, res.Error
	}
	return nil, p.ErrMalformedDirectoryMessage
}
