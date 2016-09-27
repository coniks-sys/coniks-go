// Defines constants representing the types
// of errors that the server may return to a client.

package protocol

import "errors"

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
	ErrorBadMapping
	ErrorBadSTR
	ErrorBadCommitment
	ErrorBadBinding
	ErrorCouldNotVerify
)

// ErrorResponses contains error codes that
// a response can omit the DirectoryResponse.
var ErrorResponses = map[ErrorCode]bool{
	ErrorMalformedClientMessage: true,
	ErrorDirectory:              true,
}

var (
	errorMessages = map[ErrorCode]error{
		Success:                     nil,
		ErrorMalformedClientMessage: errors.New("[coniks] Malformed client request"),
		ErrorNameExisted:            errors.New("[coniks] Registering identity is already registered"),
		ErrorNameNotFound:           errors.New("[coniks] Name not found"),
		ErrorDirectory:              errors.New("[coniks] Directory error"),

		Passed: nil,
		ErrorMalformedDirectoryMessage: errors.New("[coniks] Malformed directory message"),
		ErrorBadSignature:              errors.New("[coniks] Directory's signature is invalid"),
		ErrorBadVRFProof:               errors.New("[coniks] Bad VRF proof"),
		ErrorBadIndex:                  errors.New("[coniks] Directory returned a bad index"),
		ErrorBadMapping:                errors.New("[coniks] Returned name-to-key mapping is inconsistent with the root hash"),
		ErrorBadSTR:                    errors.New("[coniks] The hash chain is inconsistent"),
		ErrorBadCommitment:             errors.New("[coniks] Bad commitment"),
		ErrorBadBinding:                errors.New("[coniks] Bad name-to-key binding"),
		ErrorCouldNotVerify:            errors.New("[coniks] Could not verify"),
	}
)

func (e ErrorCode) Error() error {
	return errorMessages[e]
}
