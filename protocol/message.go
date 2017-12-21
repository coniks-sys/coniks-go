// Defines the message format of the CONIKS protocols
// and constructors for the response messages for each
// protocol

package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
)

// The types of requests CONIKS clients send during the CONIKS protocols.
const (
	RegistrationType = iota
	KeyLookupType
	KeyLookupInEpochType
	MonitoringType
	AuditType
	STRType
)

// A Request message defines the data a CONIKS client must send to a CONIKS
// directory for a particular request.
type Request struct {
	Type    int
	Request interface{}
}

// A RegistrationRequest is a message with a username as a string and a
// public key as bytes that a CONIKS client sends to a CONIKS directory
// to register a new entry (i.e. name-to-key binding).
// Optionally, the client can include the user's key
// change and visibility policies as boolean values in the
// request. These flags are currently unused by the CONIKS protocols.
//
// The response to a successful request is a DirectoryProof with a TB for
// the requested username and public key.
type RegistrationRequest struct {
	Username               string
	Key                    []byte
	AllowUnsignedKeychange bool `json:",omitempty"`
	AllowPublicLookup      bool `json:",omitempty"`
}

// A KeyLookupRequest is a message with a username as a string
// that a CONIKS client sends to a CONIKS directory to retrieve the
// public key bound to the given username at the latest epoch.
// If the client needs to look up a username's key for a prior epoch, it
// must send a KeyLookupInEpochRequest.
//
// The response to a successful request is a DirectoryProof with a TB if
// the requested username was registered during the latest epoch (i.e.
// the new binding hasn't been committed to the directory).
type KeyLookupRequest struct {
	Username string
}

// A KeyLookupInEpochRequest is a message with a username as a string and
// an epoch as a uint64 that a CONIKS client sends to the directory to
// retrieve the public key bound to the username in the given epoch.
// The client sends this request type when it needs to obtain
// a user's key for a past epoch. The client can send a KeyLookupRequest
// if it needs to look up a user's key for the latest epoch.
//
// The response to a successful request is a DirectoryProofs with an AP
// of length 1 containing the auth path for the requested Epoch, and a list
// of STRs covering the epoch range [Epoch, d.LatestSTR().Epoch].
type KeyLookupInEpochRequest struct {
	Username string
	Epoch    uint64
}

// A MonitoringRequest is a message with a username as a string and the
// start and end epochs of an epoch range as two uint64 that a CONIKS
// client sends to the directory to monitor the given user's key in a CONIKS
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
//
// Specifically, there are two cases for doing monitoring:
// prior history verification which can be used to verify the absence
// of the binding before registration, and name-to-key binding monitoring
// which can be used to verify the inclusion of the binding after
// registration.
type MonitoringRequest struct {
	Username   string
	StartEpoch uint64
	EndEpoch   uint64
}

// An AuditingRequest is a message with a CONIKS key directory's address
// as a string, and a StartEpoch and an EndEpoch as uint64's that a CONIKS
// client sends to a CONIKS auditor to request the given directory's
// STRs for the given epoch range. To obtain a single STR, the client
// must set StartEpoch = EndEpoch in the request.
//
// The response to a successful request is an STRHistoryRange with
// a list of STRs covering the epoch range [StartEpoch, EndEpoch].
type AuditingRequest struct {
	DirInitSTRHash [crypto.HashSizeByte]byte
	StartEpoch     uint64
	EndEpoch       uint64
}

// An STRHistoryRequest is a message with a StartEpoch and optional EndEpoch
// of an epoch range as two uint64's that a CONIKS auditor
// sends to a directory to retrieve a range of STRs starting at epoch
// StartEpoch.
//
// The response to a successful request is an STRHistoryRange with
// a list of STRs covering the epoch range [StartEpoch, EndEpoch],
// or [StartEpoch, d.LatestSTR().Epoch] if EndEpoch is omitted.
type STRHistoryRequest struct {
	StartEpoch uint64
	EndEpoch   uint64
}

// A Response message indicates the result of a CONIKS client request
// with an appropriate error code, and defines the set of cryptographic
// proofs a CONIKS directory must return as part of its response.
type Response struct {
	Error             ErrorCode
	DirectoryResponse `json:",omitempty"`
}

// A DirectoryResponse is a message that includes cryptographic proofs
// about the key directory that a CONIKS key directory or auditor returns
// to a CONIKS client.
type DirectoryResponse interface{}

// A DirectoryProof response includes a list of authentication paths
// AP for a given username-to-key binding in the directory and a list of
// signed tree roots STR for a range of epochs, and optionally
// a temporary binding for the given binding for a single epoch.
type DirectoryProof struct {
	AP  []*merkletree.AuthenticationPath
	STR []*DirSTR
	TB  *TemporaryBinding `json:",omitempty"`
}

// An STRHistoryRange response includes a list of signed tree roots
// STR representing a range of the STR hash chain. If the range only
// covers the latest epoch, the list only contains a single STR.
// A CONIKS auditor returns this DirectoryResponse type upon an
// AuditingRequest from a client, and a CONIKS directory returns
// this message upon an STRHistoryRequest from an auditor.
type STRHistoryRange struct {
	STR []*DirSTR
}

// NewErrorResponse creates a new response message indicating the error
// that occurred while a CONIKS directory or a CONIKS auditor was
// processing a client request.
func NewErrorResponse(e ErrorCode) *Response {
	return &Response{Error: e}
}

var _ DirectoryResponse = (*DirectoryProof)(nil)
var _ DirectoryResponse = (*STRHistoryRange)(nil)

// NewRegistrationProof creates the response message a CONIKS directory
// sends to a client upon a RegistrationRequest,
// and returns a Response containing a DirectoryProof struct.
// The length of `AP` and `STR` must to be equal to 1.
// directory.Register() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the registration, and
// the signed tree root for the latest epoch str.
//
// See directory.Register() for details on the contents of the created
// DirectoryProof.
func NewRegistrationProof(ap *merkletree.AuthenticationPath, str *DirSTR,
	tb *TemporaryBinding, e ErrorCode) *Response {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			AP:  append([]*merkletree.AuthenticationPath{}, ap),
			STR: append([]*DirSTR{}, str),
			TB:  tb,
		},
	}
}

// NewKeyLookupProof creates the response message a CONIKS directory
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProof struct.
// The length of `AP` and `STR` must to be equal to 1.
// directory.KeyLookup() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the key lookup, and the
// signed tree root for the latest epoch str.
//
// See directory.KeyLookup() for details on the contents of the created
// DirectoryProof.
func NewKeyLookupProof(ap *merkletree.AuthenticationPath, str *DirSTR,
	tb *TemporaryBinding, e ErrorCode) *Response {
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			AP:  append([]*merkletree.AuthenticationPath{}, ap),
			STR: append([]*DirSTR{}, str),
			TB:  tb,
		},
	}
}

// NewKeyLookupInEpochProof creates the response message a CONIKS directory
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.KeyLookupInEpoch() passes an authentication path ap and error
// code e according to the result of the lookup, and a list of signed
// tree roots for the requested range of epochs str.
//
// See directory.KeyLookupInEpoch() for details on the contents of the
// created DirectoryProofs.
func NewKeyLookupInEpochProof(ap *merkletree.AuthenticationPath,
	str []*DirSTR, e ErrorCode) *Response {
	aps := append([]*merkletree.AuthenticationPath{}, ap)
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProof{
			AP:  aps,
			STR: str,
		},
	}
}

// NewMonitoringProof creates the response message a CONIKS directory
// sends to a client upon a MonitoringRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.Monitor() passes a list of authentication paths ap and a
// list of signed tree roots for the requested range of epochs str.
//
// See directory.Monitor() for details on the contents of the created
// DirectoryProofs.
func NewMonitoringProof(ap []*merkletree.AuthenticationPath,
	str []*DirSTR) *Response {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProof{
			AP:  ap,
			STR: str,
		},
	}
}

// NewSTRHistoryRange creates the response message a CONIKS auditor
// sends to a client upon an AuditingRequest,
// and returns a Response containing an STRHistoryRange struct.
// auditlog.GetObservedSTRs() passes a list of one or more signed tree roots
// that the auditor observed for the requested range of epochs str.
//
// See auditlog.GetObservedSTRs() for details on the contents of the created
// STRHistoryRange.
func NewSTRHistoryRange(str []*DirSTR) *Response {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &STRHistoryRange{
			STR: str,
		},
	}
}

// Validate returns immediately if the message includes an error code.
// Otherwise, it verifies whether the message has proper format.
func (msg *Response) Validate() error {
	if errors[msg.Error] {
		return msg.Error
	}

	if msg.DirectoryResponse == nil {
		return ErrMalformedMessage
	}
	switch df := msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		if len(df.STR) == 0 || len(df.AP) == 0 {
			return ErrMalformedMessage
		}
		return nil
	case *STRHistoryRange:
		if len(df.STR) == 0 {
			return ErrMalformedMessage
		}
		return nil
	default:
		panic("[coniks] Malformed response")
	}
}

// GetKey returns the key extracted from
// a validated CONIKS directory's response.
//
// If the response contains a single authentication path,
// the key is obtained from that authentication path or the
// temporary binding, depending on the returned proof type.
//
// If the response contains a range of authentication paths,
// the key is obtained from the authentication path corresponding
// to the most recent signed tree root.
// FIXME: remove this obsolete function
func (msg *Response) GetKey() ([]byte, error) {
	return nil, nil
}
