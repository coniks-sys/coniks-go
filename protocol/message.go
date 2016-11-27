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
// public key bound to the given username at the latest epoch.
// If the client needs to look up a username's key for a prior epoch, it
// must send a KeyLookupInEpochRequest.
//
// The response to a successful request is a DirectoryProof with a TB if the requested
// username was registered during the latest epoch (i.e. the new binding hasn't been
// committed to the directory).
type KeyLookupRequest struct {
	Username string `json:"username"`
}

// A KeyLookupInEpochRequest is a message with a username as a string and
// an epoch as a uint64 that a CONIKS client sends to the server to
// retrieve the public key bound to the username in the given epoch.
// The client sends this request type when it needs to obtain
// a user's key for a past epoch. The client can send a KeyLookupRequest
// if it needs to look up a user's key for the latest epoch.
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

// A DirectoryResponse is a message that includes cryptographic proofs
// about the key directory that a CONIKS key server returns to a
// CONIKS client.
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
// sends to a client upon a RegistrationRequest,
// and returns a Response containing a DirectoryProof struct.
// directory.Register() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the registration, and the signed
// tree root for the latest epoch str.
//
// See directory.Register() for details on the contents of the created
// DirectoryProof.
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
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProof struct.
// directory.KeyLookup() passes an authentication path ap, temporary binding
// tb and error code e according to the result of the key lookup, and the signed
// tree root for the latest epoch str.
//
// See directory.KeyLookup() for details on the contents of the created
// DirectoryProof.
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
// sends to a client upon a KeyLookupRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.KeyLookupInEpoch() passes an authentication path ap and error code e
// according to the result of the lookup, and a list of signed
// tree roots for the requested range of epochs str.
//
// See directory.KeyLookupInEpoch() for details on the contents of the created
// DirectoryProofs.
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

// NewMonitoringProof creates the response message a CONIKS server
// sends to a client upon a MonitoringRequest,
// and returns a Response containing a DirectoryProofs struct.
// directory.Monitor() passes a list of authentication paths ap and a
// list of signed tree roots for the requested range of epochs str.
//
// See directory.Monitor() for details on the contents of the created
// DirectoryProofs.
func NewMonitoringProof(ap []*m.AuthenticationPath,
	str []*m.SignedTreeRoot) (*Response, ErrorCode) {
	return &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProofs{
			AP:  ap,
			STR: str,
		},
	}, ReqSuccess
}

// GetKey returns the key extracted from
// a _verified_ CONIKS server's response.
//
// If the response contains a single authentication path,
// the key is obtained from that authentication path or the
// temporary binding (which depends on the returned proof type).
//
// If the response contains a range of authentication paths,
// the key is obtained from the authentication path corresponding
// with the most recent signed tree root.
func (msg *Response) GetKey() []byte {
	switch df := msg.DirectoryResponse.(type) {
	case *DirectoryProof:
		if df.AP.ProofType() == m.ProofOfAbsence {
			if df.TB != nil { // FIXME: this check could be eliminated when we force to use TB?
				return df.TB.Value
			}
			return nil
		}
		return df.AP.Leaf.Value
	case *DirectoryProofs:
		return df.AP[len(df.AP)-1].Leaf.Value
	default:
		return nil
	}
}
