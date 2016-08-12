package protocol

import (
	m "github.com/coniks-sys/coniks-go/merkletree"
)

// Defines constants representing the types
// of messages exchanged by clients and servers.
const (
	RegistrationType = iota
)

// Request messages
type Request struct {
	Type    int
	Request interface{}
}

type RegistrationRequest struct {
	Username               string `json:"username"`
	Key                    []byte `json:"key"`
	AllowUnsignedKeychange bool   `json:"allow_unsigned_key_change,omitempty"`
	AllowPublicLookup      bool   `json:"allow_public_lookup,omitempty"`
}

// Response messages
type Response interface{}

type ErrorResponse struct {
	Error ErrorCode
}

func NewErrorResponse(e ErrorCode) Response {
	return &ErrorResponse{Error: e}
}

type DirectoryProof struct {
	Type int
	AP   *m.AuthenticationPath
	STR  *m.SignedTreeRoot
	TB   *m.TemporaryBinding `json:",omitempty"`
}

func NewRegistrationProof(ap *m.AuthenticationPath, str *m.SignedTreeRoot,
	tb *m.TemporaryBinding) *DirectoryProof {
	return &DirectoryProof{RegistrationType, ap, str, tb}
}
