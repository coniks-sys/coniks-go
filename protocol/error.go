// Defines constants representing the types
// of errors that the server may return to a client.

package protocol

type ErrorCode int

const (
	Success ErrorCode = iota + 10
	ErrorDirectory
	ErrorNameExisted
	ErrorNameNotFound
	ErrorMalformedClientMessage
)

const (
	Passed ErrorCode = iota + 20
	ErrorMalformedDirectoryMessage
	ErrorBadSignature
	ErrorBadVRFProof
	ErrorBadIndex
	ErrorBadAuthPath
	ErrorBadSTR
	ErrorBadCommitment
	ErrorBadBinding
	ErrorCouldNotVerify
	ErrorBadPromise
	ErrorBreakPromise
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
		ErrorBadIndex:                  "[coniks] The index in the TB and the index in the auth path do not match",
		ErrorBadAuthPath:               "[coniks] Returned binding is inconsistent with the tree root hash",
		ErrorBadSTR:                    "[coniks] The hash chain is inconsistent",
		ErrorBadCommitment:             "[coniks] The binding commitment is invalid",
		ErrorBadBinding:                "[coniks] Key in the binding is inconsistent",
		ErrorCouldNotVerify:            "[coniks] Could not verify",
		ErrorBadPromise:                "[coniks] The directory returned an invalid registration promise",
		ErrorBreakPromise:              "[coniks] The directory broke the registration promise",
	}
)

func (e ErrorCode) Error() string {
	return errorMessages[e]
}
