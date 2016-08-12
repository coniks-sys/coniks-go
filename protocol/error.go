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

var (
	errorMessages = map[ErrorCode]error{
		ErrorMalformedClientMessage: errors.New("[coniks] Malformed client request"),
		ErrorNameExisted:            errors.New("[coniks] Registering identity is already registered"),
		ErrorNameNotFound:           errors.New("[coniks] Name not found"),
		ErrorDirectory:              errors.New("[coniks] Directory error"),
	}
)

func (e ErrorCode) Error() error {
	if errorMessages[e] == nil {
		return errorMessages[ErrorDirectory]
	}
	return errorMessages[e]
}
