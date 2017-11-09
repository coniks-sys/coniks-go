package binutils

import (
	"encoding/json"
	"log"

	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

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
		if !protocol.Errors[res.Error] {
			return &protocol.Response{
				Error: protocol.ErrMalformedMessage,
			}
		}
		return &protocol.Response{
			Error: res.Error,
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
	case protocol.AuditType, protocol.STRType:
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

// MarshalSTRToFile serializes the given STR to the given path.
func MarshalSTRToFile(str *protocol.DirSTR, path string) {
	strBytes, err := json.Marshal(str)
	if err != nil {
		log.Print(err)
		return
	}

	if err := utils.WriteFile(path, strBytes, 0600); err != nil {
		log.Println(err)
		return
	}
}
