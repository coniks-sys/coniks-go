package client

import (
	"encoding/json"

	p "github.com/coniks-sys/coniks-go/protocol"
	//"fmt"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// UnmarshalResponse decodes the given message into a protocol.DirectoryResponse
// according to the given request-type t. This request-types are integer
// constants defined in the protocol package.
func UnmarshalResponse(t int, msg []byte) (
	p.DirectoryResponse, p.ErrorCode) {
	type Response struct {
		Error             p.ErrorCode
		DirectoryResponse json.RawMessage
	}
	var res Response
	if err := json.Unmarshal(msg, &res); err != nil {
		return nil, p.ErrMalformedDirectoryMessage
	}

	// DirectoryResponse is omitempty for the places
	// where Error is in Errors
	if res.DirectoryResponse == nil {
		if !p.Errors[res.Error] {
			return nil, p.ErrMalformedDirectoryMessage
		}
		return nil, res.Error
	}

	switch t {
	case p.RegistrationType, p.KeyLookupType:
		response := new(p.DirectoryProof)
		if err := json.Unmarshal(res.DirectoryResponse, &response); err != nil {
			// FIXME: Without the ugly hack in str.go fmt.Println(err) yields:
			// json: cannot unmarshal object into Go value of type merkletree.AssocData
			// fmt.Println("json.Unmarshal(res.DirectoryResponse, &response)", err)
			return nil, p.ErrMalformedDirectoryMessage
		}
		// FIXME totally ugly hack:
		ad := response.STR.Ad.(*merkletree.FIXMEPolicies)
		response.STR.Ad = &p.Policies{
			Version:       ad.Version,
			HashID:        ad.HashID,
			VrfPublicKey:  ad.VrfPublicKey,
			EpochDeadline: p.Timestamp(ad.EpochDeadline),
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
