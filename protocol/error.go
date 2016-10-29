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
	PassedWithAProofOfAbsence ErrorCode = iota + 20
	PassedWithAProofOfInclusion
	ErrorMalformedDirectoryMessage
	ErrorBadProofType
	ErrorBadSignature
	ErrorBadVRFProof
	ErrorBadIndex
	ErrorBadAuthPath
	ErrorBadSTR
	ErrorBadCommitment
	ErrorBadBinding
	ErrorBadPromise
	ErrorBrokenPromise
)

// ErrorResponses contains error codes indicating the client
// should omit the consistency checks. These errors indicate
// that either a client request could not be processed due to
// a malformed client request, an internal server error or
// due to a malformed server response.
var ErrorResponses = map[ErrorCode]bool{
	ErrorMalformedDirectoryMessage: true,
	ErrorMalformedClientMessage:    true,
	ErrorDirectory:                 true,
}

var (
	errorMessages = map[ErrorCode]string{
		Success:                     "[coniks] Successful client request",
		ErrorMalformedClientMessage: "[coniks] Malformed client message",
		ErrorNameExisted:            "[coniks] Registering identity is already registered",
		ErrorNameNotFound:           "[coniks] Searched name not found in directory",
		ErrorDirectory:              "[coniks] Directory error",

		PassedWithAProofOfAbsence:      "[coniks] Consistency checks passed with a proof of absence",
		PassedWithAProofOfInclusion:    "[coniks] Consistency checks passed with a proof of inclusion",
		ErrorMalformedDirectoryMessage: "[coniks] Malformed directory message",
		ErrorBadProofType:              "[coniks] The directory returned an unexpected proof type for the request",
		ErrorBadSignature:              "[coniks] Directory's signature on STR or TB is invalid",
		ErrorBadVRFProof:               "[coniks] Returned index is not valid for the given name",
		ErrorBadIndex:                  "[coniks] The index in the TB and the index in the auth path do not match",
		ErrorBadAuthPath:               "[coniks] Returned binding is inconsistent with the tree root hash",
		ErrorBadSTR:                    "[coniks] The hash chain is inconsistent",
		ErrorBadCommitment:             "[coniks] The binding commitment is invalid",
		ErrorBadBinding:                "[coniks] Key in the binding is inconsistent",
		ErrorBadPromise:                "[coniks] The directory returned an invalid registration promise",
		ErrorBrokenPromise:             "[coniks] The directory broke the registration promise",
	}
)

func (e ErrorCode) Error() string {
	return errorMessages[e]
}
