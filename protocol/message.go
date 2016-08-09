package protocol

import "github.com/coniks-sys/coniks-go/merkletree"

// Defines constants representing the types
// of messages exchanged by clients and servers.
const (
	RegistrationType = 0
)

type Request struct {
	Type    int
	Request interface{}
}

type Response interface{}

type ErrorResponse struct {
	Error ErrorCode
}

func NewErrorResponse(e ErrorCode) Response {
	return &ErrorResponse{Error: e}
}

type RegistrationRequest struct {
	Username               string `json:"username"`
	Key                    string `json:"key"`
	AllowUnsignedKeychange bool   `json:"allow_unsigned_key_change,omitempty"`
	AllowPublicLookup      bool   `json:"allow_public_lookup,omitempty"`
}

type RegistrationResponse struct {
	Type int
	STR  *merkletree.SignedTreeRoot
	AP   *merkletree.AuthenticationPath
}

// RegistrationResponseWithTB is used to replace RegistrationResponse
// with addition TB field
type RegistrationResponseWithTB struct {
	Type int
	STR  *merkletree.SignedTreeRoot
	AP   *merkletree.AuthenticationPath
	TB   *merkletree.TemporaryBinding
}
