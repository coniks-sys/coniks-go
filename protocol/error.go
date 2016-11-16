// Defines constants representing the types
// of errors that the server may return to a client,
// and that the client may throw after a consistency
// check or a cryptographic verification

package protocol

// An ErrorCode implements the built-in error interface type.
type ErrorCode int

// Server-client status codes: These codes are being used
// to exchange between the server and the client.
// Codes prefixed by "Req" indicate different request results.
// Codes prefixed by "Error" indicate a request fails or a malformed response.
const (
	ReqSuccess ErrorCode = iota + 100
	ReqNameExisted
	ReqNameNotFound

	ErrDirectory
	ErrMalformedClientMessage
	ErrMalformedDirectoryMessage
)

// These codes indicate the result
// of a consistency check or cryptographic verification.
// These codes are prefixed by "Check".
const (
	CheckPassed ErrorCode = iota + 200
	CheckBadSignature
	CheckBadVRFProof
	CheckBadAuthPath
	CheckBadSTR
	CheckBadPromise
	CheckBrokenPromise
)

// Errors contains codes indicating the client
// should omit the consistency checks. These errors indicate
// that either a client request could not be processed due to
// a malformed client request, an internal server error or
// due to a malformed server response.
var Errors = map[ErrorCode]bool{
	ErrMalformedClientMessage:    true,
	ErrDirectory:                 true,
	ErrMalformedDirectoryMessage: true,
}

var (
	errorMessages = map[ErrorCode]string{
		ReqSuccess:      "[coniks] Successful client request",
		ReqNameExisted:  "[coniks] Registering identity is already registered",
		ReqNameNotFound: "[coniks] Searched name not found in directory",

		ErrMalformedClientMessage:    "[coniks] Malformed client message",
		ErrDirectory:                 "[coniks] Directory error",
		ErrMalformedDirectoryMessage: "[coniks] Malformed directory message",

		CheckPassed:        "[coniks] Consistency checks passed",
		CheckBadSignature:  "[coniks] Directory's signature on STR or TB is invalid",
		CheckBadVRFProof:   "[coniks] Returned index is not valid for the given name",
		CheckBadAuthPath:   "[coniks] Returned binding is inconsistent with the tree root hash",
		CheckBadSTR:        "[coniks] The hash chain is inconsistent",
		CheckBadPromise:    "[coniks] The directory returned an invalid registration promise",
		CheckBrokenPromise: "[coniks] The directory broke the registration promise",
	}
)

// Returns the error message corresponding to the error code e.
func (e ErrorCode) Error() string {
	return errorMessages[e]
}
