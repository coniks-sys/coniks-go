// Defines the message format of the CONIKS protocols
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
// as a string that a CONIKS client sends to a CONIKS auditor to request
// the latest STR the auditor has observed for the given directory.
// If the client needs to request a directory's STR for a prior epoch, it
// must send an AuditingInEpochRequest.
//
// The response to a successful request is an ObservedDirectoryProof.
type AuditingRequest struct {
	DirectoryAddr string `json:"directory_addr"`
}

// An AuditingInEpochRequest is a message with a key directory's address
// as a string and an epoch as a uint64 that a CONIKS client sends to
// a CONIKS auditor to retrieve the STR it observed for the directory in
// the given epoch. The client sends this request type when it needs to
// audit a directory's STR for a prior epoch (i.e. as part of a
// key lookup in epoch check or a monitoring check). The client can send an
// AuditingRequest if it needs to audit a directory's STR for its latest
// epoch.
//
// The response to a successful request is an ObservedDirectoryProofs with
// a list of STRs covering the epoch range [Epoch, d.LatestSTR().Epoch].
type AuditingInEpochRequest struct {
	DirectoryAddr string `json:"directory_addr"`
	Epoch         uint64 `json:"epoch"`
}

// An AuditingRequest is a message with a CONIKS key directory's address
// as a string that a CONIKS client sends to a CONIKS auditor to request
// the latest STR the auditor has observed for the given directory.
// If the client needs to request a directory's STR for a prior epoch, it
// must send an AuditingInEpochRequest.
//
// The response to a successful request is an ObservedDirectoryProof.
type AuditingRequest struct {
	DirectoryAddr string `json:"directory_addr"`
}

// An AuditingInEpochRequest is a message with a key directory's address
// as a string and an epoch as a uint64 that a CONIKS client sends to
// a CONIKS auditor to retrieve the STR it observed for the directory in
// the given epoch. The client sends this request type when it needs to
// audit a directory's STR for a prior epoch (i.e. as part of a
// key lookup in epoch check or a monitoring check). The client can send an
// AuditingRequest if it needs to audit a directory's STR for its latest
// epoch.
//
// The response to a successful request is an ObservedDirectoryProofs with
// a list of STRs covering the epoch range [Epoch, d.LatestSTR().Epoch].
type AuditingInEpochRequest struct {
	DirectoryAddr string `json:"directory_addr"`
	Epoch         uint64 `json:"epoch"`
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

// A DirectoryProof response includes an authentication path AP for a
// given username-to-key binding in the directory, a signed tree root
// STR, and optionally a temporary binding for the given binding for a
// single epoch. A CONIKS directory returns this DirectoryResponse
// type upon a RegistrationRequest or a KeyLookupRequest.
type DirectoryProof struct {
	AP  *m.AuthenticationPath
	STR *DirSTR
	TB  *TemporaryBinding `json:",omitempty"`
}

// A DirectoryProofs response includes a list of authentication paths
// AP for a given username-to-key binding in the directory and a list of
// signed tree roots STR for a range of epochs. A CONIKS directory returns
// this DirectoryResponse type upon a KeyLookupInEpochRequest or a
// MonitoringRequest.
type DirectoryProofs struct {
	AP  []*m.AuthenticationPath
	STR []*DirSTR
}

// An ObservedSTR response includes a single signed tree root
// STR. A CONIKS auditor returns this DirectoryResponse type upon an
// AuditingRequest.
type ObservedSTR struct {
	STR *m.SignedTreeRoot
}

// An ObservedSTRs response includes a list of signed tree roots
// STR. A CONIKS auditor returns this DirectoryResponse type upon an
// AudutingRequest.
type ObservedSTRs struct {
	STR []*m.SignedTreeRoot
}

// An ObservedSTR response includes a single signed tree root
// STR. A CONIKS auditor returns this DirectoryResponse type upon an
// AuditingRequest.
type ObservedSTR struct {
	STR *m.SignedTreeRoot
}

// An ObservedSTRs response includes a list of signed tree roots
// STR. A CONIKS auditor returns this DirectoryResponse type upon an
// AudutingRequest.
type ObservedSTRs struct {
	STR []*m.SignedTreeRoot
}

// NewErrorResponse creates a new response message indicating the error
// that occurred while a CONIKS directory or a CONIKS auditor was
// processing a client request.
func NewErrorResponse(e ErrorCode) *Response {
	return &Response{Error: e}
}

var _ DirectoryResponse = (*DirectoryProof)(nil)
var _ DirectoryResponse = (*DirectoryProofs)(nil)
var _ DirectoryResponse = (*ObservedSTR)(nil)
var _ DirectoryResponse = (*ObservedSTRs)(nil)

// NewRegistrationProof creates the response message a CONIKS directory
// sends to a client upon a RegistrationRequest,
// and returns a Response containing a DirectoryProof struct.
// directory.Register() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the registration, and
// the signed tree root for the latest epoch str.
//
// See directory.Register() for details on the contents of the created
// DirectoryProof.
func NewRegistrationProof(ap *m.AuthenticationPath, str *DirSTR,
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

// NewKeyLookupProof creates the response message a CONIKS directory
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProof struct.
// directory.KeyLookup() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the key lookup, and the
// signed tree root for the latest epoch str.
//
// See directory.KeyLookup() for details on the contents of the created
// DirectoryProof.
func NewKeyLookupProof(ap *m.AuthenticationPath, str *DirSTR,
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

// NewKeyLookupInEpochProof creates the response message a CONIKS directory
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.KeyLookupInEpoch() passes an authentication path ap and error
// code e according to the result of the lookup, and a list of signed
// tree roots for the requested range of epochs str.
//
// See directory.KeyLookupInEpoch() for details on the contents of the
// created DirectoryProofs.
func NewKeyLookupInEpochProof(ap *m.AuthenticationPath,
	str []*DirSTR, e ErrorCode) (*Response, ErrorCode) {
	aps := append([]*m.AuthenticationPath{}, ap)
	return &Response{
		Error: e,
		DirectoryResponse: &DirectoryProofs{
			AP:  aps,
			STR: str,
		},
	}, e
}

// NewMonitoringProof creates the response message a CONIKS directory
// sends to a client upon a MonitoringRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.Monitor() passes a list of authentication paths ap and a
// list of signed tree roots for the requested range of epochs str.
//
// See directory.Monitor() for details on the contents of the created
// DirectoryProofs.
func NewMonitoringProof(ap []*m.AuthenticationPath,
	str []*DirSTR) (*Response, ErrorCode) {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProofs{
			AP:  ap,
			STR: str,
		},
	}, ReqSuccess
}

// NewObservedSTR creates the response message a CONIKS auditor
// sends to a client upon an AuditingRequest,
// and returns a Response containing an ObservedSTR struct.
// auditlog.Audit() passes the signed tree root for the auditor's latest
// observed epoch str.
//
// See auditlog.Audit() for details on the contents of the created
// ObservedSTR.
func NewObservedSTR(str *m.SignedTreeRoot) (*Response, ErrorCode) {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &ObservedSTR{
			STR: str,
		},
	}, ReqSuccess
}

// NewObservedSTRs creates the response message a CONIKS auditor
// sends to a client upon an AuditingInEpochRequest,
// and returns a Response containing an ObservedSTRs struct.
// auditlog.AuditInEpoch() passes a list of signed tree roots
// that the auditor observed for the requested range of epochs str.
//
// See auditlog.AuditInEpoch() for details on the contents of the created
// ObservedSTRs.
func NewObservedSTRs(str []*m.SignedTreeRoot) (*Response, ErrorCode) {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &ObservedSTRs{
			STR: str,
		},
	}, ReqSuccess
}

func (msg *Response) validate() error {
	if Errors[msg.Error] {
		return msg.Error
	}
	switch df := msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		if df.AP == nil || df.STR == nil {
			return ErrMalformedDirectoryMessage
		}
		return nil
	case *DirectoryProofs:
		// TODO: also do above assertions here
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
func (msg *Response) GetKey() ([]byte, error) {
	if err := msg.validate(); err != nil {
		return nil, err
	}
	switch df := msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		if df.AP.ProofType() == m.ProofOfAbsence {
			if df.TB != nil { // FIXME: this check could be eliminated when we force to use TB?
				return df.TB.Value, nil
			}
			return nil, nil
		}
		return df.AP.Leaf.Value, nil
	case *DirectoryProofs:
		return df.AP[len(df.AP)-1].Leaf.Value, nil
	default:
		panic("[coniks] Malformed response")
	}
}
