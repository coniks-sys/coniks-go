// Defines the message formats of the CONIKS protocols
// and constructors for the response messages for each
// protocol

package protocol

import m "github.com/coniks-sys/coniks-go/merkletree"

// The types of requests CONIKS clients send during the CONIKS protocols.
const (
	RegistrationType = iota
	KeyLookupType
	KeyLookupInEpochType
	MonitoringType
)

// A Request message defines the data a CONIKS client must send to a CONIKS
// server for a particular request.
type Request struct {
	Type    int
	Request interface{}
}

// A RegistrationRequest is a message with a username as a string and a
// public key as bytes that a CONIKS client sends to a CONIKS server
// to register a new entry (i.e. name-to-key binding) with a CONIKS
// key directory. Optionally, the client can include the user's key
// change and visibility policies as boolean values in the
// request. These flags are currently unused by the CONIKS protocols.
//
// The response to a successful request is a DirectoryProof with a TB for
// the requested username and public key.
type RegistrationRequest struct {
	Username               string `json:"username"`
	Key                    []byte `json:"key"`
	AllowUnsignedKeychange bool   `json:"allow_unsigned_key_change,omitempty"`
	AllowPublicLookup      bool   `json:"allow_public_lookup,omitempty"`
}

// A KeyLookupRequest is a message with a username as a string
// that a CONIKS client sends to a CONIKS server to retrieve the
// public key bound to the given username at the current epoch.
// If the client needs to look up a username's key for a prior epoch, it
// must send a KeyLookupInEpochRequest.
//
// The response to a successful request is a DirectoryProof with a TB if the requested
// username was registered during the current epoch (i.e. the new binding hasn't been
// committed to the directory).
type KeyLookupRequest struct {
	Username string `json:"username"`
}

// A KeyLookupInEpochRequest is a message with a username as a string and
// an epoch as a uint64 that a CONIKS client sends to the server to
// retrieve the public key bound to the username in the given epoch.
// The client sends this request type when it needs to obtain
// a user's key for a past epoch. The client can send a KeyLookupRequest
// if it needs to look up a user's key for the current epoch.
//
// The response to a successful request is a DirectoryProofs with an AP
// of length 1 containing the auth path for the requested Epoch, and an
// STR covering the epoch range [Epoch, d.LatestSTR().Epoch].
type KeyLookupInEpochRequest struct {
	Username string `json:"username"`
	Epoch    uint64 `json:"epoch"`
}

// A MonitoringRequest is a message with a username as a string and the
// start and end epochs of an epoch range as two uint64 that a CONIKS
// client sends to the server to monitor the given user's key in a CONIKS
// key directory, i.e. to ensure that the key bound to the username hasn't
// changed unexpectedly.
//
// If the client needs to check the consistency of a user's binding for
// a range of epochs (e.g. if the client went offline for several epochs
// and was unable to monitor its user's binding during that period),
// it indicates the beginning of the range with the start epoch, and the
// end of the range with the end epoch. An end epoch with a value greater
// than the key directory's latest
// epoch sets the end of the epoch range at the directory's latest epoch.
type MonitoringRequest struct {
	Username   string `json:"username"`
	StartEpoch uint64 `json:"start_epoch"`
	EndEpoch   uint64 `json:"end_epoch"`
}

// A Response message indicates the result of a CONIKS client request
// with an appropriate error code, and defines the set of cryptographic
// proofs a CONIKS server must return as part of its response.
type Response struct {
	Error             ErrorCode
	DirectoryResponse `json:",omitempty"`
}

// A CONIKS server sends a DirectoryResponse message when it returns cryptographic proofs
// about the key directory to a CONIKS client.
type DirectoryResponse interface{}

// A DirectoryProof response includes an authentication path AP for a
// given username-to-key binding in the directory, a signed tree root
// STR, and optionally a temporary binding for the given binding for a
// single epoch. A CONIKS server returns this DirectoryResponse
// type upon a RegistrationRequest or a KeyLookupRequest.
type DirectoryProof struct {
	AP  *m.AuthenticationPath
	STR *m.SignedTreeRoot
	TB  *TemporaryBinding `json:",omitempty"`
}

// A DirectoryProofs response includes a list of authentication paths
// AP for a given username-to-key binding in the directory and a list of
// signed tree roots STR for a range of epochs. A CONIKS server returns
// this DirectoryResponse
// type upon a KeyLookupInEpochRequest or a MonitoringRequest.
type DirectoryProofs struct {
	AP  []*m.AuthenticationPath
	STR []*m.SignedTreeRoot
}

// NewErrorResponse creates a new response message indicating the error
// that occurred while a CONIKS server was processing a client request.
func NewErrorResponse(e ErrorCode) *Response {
	return &Response{Error: e}
}

var _ DirectoryResponse = (*DirectoryProof)(nil)
var _ DirectoryResponse = (*DirectoryProofs)(nil)

// NewRegistrationProof creates the response message a CONIKS server
// sends to a client upon a RegistrationRequest.
// The contained DirectoryProof is either a proof of absence with a temporary
// binding in the case of a successful registration (e = Success), or a
// proof of inclusion in the case that the requested name already exists
// in the directory (e = ErrorNameExisted).
// If the requested name has already been registered but not yet
// committed to the directory,
// the DirectoryProof returns a proof of absence with the corresponding
// TB, but sets the error code to ErrorNameExisted.
// In all cases, the sserver must also include the signed tree root
// (STR) for the lastest epoch.
func NewRegistrationProof(ap *m.AuthenticationPath, str *m.SignedTreeRoot,
	tb *TemporaryBinding, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			AP:  ap,
			STR: str,
			TB:  tb,
		},
	}, e
}

// NewKeyLookupProof creates the response message a CONIKS server
// sends to a client upon a KeyLookupRequest.
// The contained DirectoryProof is either a proof of inclusion without a
// temporary binding (e = Success), or a proof of absence if the requested
// name does not exist in the directory (e = ErrorNameNotFound).
// If the requested name has already been registered but not yet
// committed to the directory, the DirectoryProof returns a proof of
// absence with the corresponding TB, but sets the error code to Success.
// In all cases, the sserver must also include the signed tree root (STR)
// for the lastest epoch.
func NewKeyLookupProof(ap *m.AuthenticationPath, str *m.SignedTreeRoot,
	tb *TemporaryBinding, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			AP:  ap,
			STR: str,
			TB:  tb,
		},
	}, e
}

// NewKeyLookupInEpochProof creates the response message a CONIKS server
// sends to a client upon a KeyLookupInEpochRequest.
// The contained DirectoryProofs is either a single proof of inclusion
// (e = Success), or a proof of absence if the requested name does not
// exist in the directory (e = ErrorNameNotFound).
// In either case, the server returns a list of STRs for the epoch range [ep,
// directory.LatestEpoch().Epoch], where ep is the past epoch for which
// the client has requested the user's key.
func NewKeyLookupInEpochProof(ap *m.AuthenticationPath,
	str []*m.SignedTreeRoot, e ErrorCode) (*Response, ErrorCode) {
	aps := append([]*m.AuthenticationPath{}, ap)
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProofs{
			AP:  aps,
			STR: str,
		},
	}, e
}

// NewMonitoringProof creates the response message a CONIKS server sends
// to a client upon a MonitoringRequest. The contained DirectoryProofs
// includes a list of proofs of inclusion and a list
// of STRs for the epoch range [startEpoch, endEpoch], where startEpoch
// and endEpoch are the epoch range endpoints indicated in the client's
// request. The error code is set to Success.
func NewMonitoringProof(ap []*m.AuthenticationPath,
	str []*m.SignedTreeRoot, e ErrorCode) (*Response, ErrorCode) {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProofs{
			AP:  ap,
			STR: str,
		},
	}, e
}
