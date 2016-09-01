package protocol

import (
	m "github.com/coniks-sys/coniks-go/merkletree"
)

// Defines constants representing the types
// of messages exchanged by clients and servers.
const (
	RegistrationType = iota
	KeyLookupType
	KeyLookupInEpochType
	MonitoringType
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

type KeyLookupRequest struct {
	Username string `json:"username"`
}

// KeyLookupInEpochRequest is used for querying
// the key in the past epoch.
// The response should only return the AP for the querying Epoch
// and all STRs in the range [Epoch, currentDirectoryEpoch]
type KeyLookupInEpochRequest struct {
	Username string `json:"username"`
	Epoch    uint64 `json:"epoch"`
}

// MonitoringRequest is used for monitoring
// user's key in the directory.
// The response should return all APs and STRs
// in range [StartEpoch, EndEpoch].
// Notice that the returned number of STRs
// does not exceed (currentDirectoryEpoch - StartEpoch)
type MonitoringRequest struct {
	Username   string `json:"username"`
	StartEpoch uint64 `json:"start_epoch"`
	EndEpoch   uint64 `json:"end_epoch"`
}

// Response messages
type Response struct {
	Error             ErrorCode
	DirectoryResponse `json:",omitempty"`
}

type DirectoryResponse interface{}

type DirectoryProof struct {
	Type int
	AP   *m.AuthenticationPath
	STR  *m.SignedTreeRoot
	TB   *m.TemporaryBinding `json:",omitempty"`
}

type DirectoryProofs struct {
	Type int
	AP   []*m.AuthenticationPath
	STR  []*m.SignedTreeRoot
}

func NewErrorResponse(e ErrorCode) *Response {
	return &Response{Error: e}
}

func NewRegistrationProof(ap *m.AuthenticationPath, str *m.SignedTreeRoot,
	tb *m.TemporaryBinding, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			Type: RegistrationType,
			AP:   ap,
			STR:  str,
			TB:   tb,
		},
	}, e
}

func NewKeyLookupProof(ap *m.AuthenticationPath, str *m.SignedTreeRoot,
	tb *m.TemporaryBinding, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			Type: KeyLookupType,
			AP:   ap,
			STR:  str,
			TB:   tb,
		},
	}, e
}

func NewKeyLookupInEpochProof(ap *m.AuthenticationPath,
	str []*m.SignedTreeRoot, e ErrorCode) (*Response, ErrorCode) {
	aps := append([]*m.AuthenticationPath{}, ap)
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProofs{
			Type: KeyLookupInEpochType,
			AP:   aps,
			STR:  str,
		},
	}, e
}

func NewMonitoringProof(ap []*m.AuthenticationPath,
	str []*m.SignedTreeRoot, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProofs{
			Type: MonitoringType,
			AP:   ap,
			STR:  str,
		},
	}, e
}
