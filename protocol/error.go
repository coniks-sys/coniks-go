// Defines constants representing the types
// of errors that the server may return to a client,
// and that the client may throw after a consistency
// check or cryptographic verification

package protocol

// ErrorCodes are special ints
type ErrorCode int

// Server-side errors: The server returns these errors
// to the client when a request fails
const (
	Success ErrorCode = iota + 10
	ErrorDirectory
	ErrorNameExisted
	ErrorNameNotFound
	ErrorMalformedClientMessage
)

// Client-side errors: The client throws these errors
// when a consistency check or cryptographic verification
// fails
const (
	Passed ErrorCode = iota + 20
	ErrorMalformedDirectoryMessage
	ErrorBadSignature
	ErrorBadVRFProof
	ErrorBadAuthPath
	ErrorBadSTR
	ErrorBadPromise
	ErrorBrokenPromise
)

// ErrorResponses contains error codes that
// a response can omit the DirectoryResponse.
var ErrorResponses = map[ErrorCode]bool{
	ErrorMalformedClientMessage: true,
	ErrorDirectory:              true,
}

var (
	errorMessages = map[ErrorCode]string{
		Success:                     "[coniks] Successful client request",
		ErrorMalformedClientMessage: "[coniks] Malformed client message",
		ErrorNameExisted:            "[coniks] Registering identity is already registered",
		ErrorNameNotFound:           "[coniks] Searched name not found in directory",
		ErrorDirectory:              "[coniks] Directory error",

		Passed: "[coniks] Consistency checks passed",
		ErrorMalformedDirectoryMessage: "[coniks] Malformed directory message",
		ErrorBadSignature:              "[coniks] Directory's signature on STR or TB is invalid",
		ErrorBadVRFProof:               "[coniks] Returned index is not valid for the given name",
		ErrorBadAuthPath:               "[coniks] Returned binding is inconsistent with the tree root hash",
		ErrorBadSTR:                    "[coniks] The hash chain is inconsistent",
		ErrorBadPromise:                "[coniks] The directory returned either an invalid registration promise or no promise",
		ErrorBrokenPromise:             "[coniks] The directory broke the registration promise by not inserting the binding to the tree in the expected epoch",
	}
)

// Returns the error message corresponding to e
func (e ErrorCode) Error() string {
	return errorMessages[e]
}
