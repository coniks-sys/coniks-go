// Defines constants representing the types
// of errors that the server may return to a client.

package protocol

import "errors"

type ErrorCode int

const (
	Success ErrorCode = iota + 10
	ErrorInternalServer
	ErrorNameExisted
	ErrorMalformedClientMessage
)

var (
	errorMessages = map[ErrorCode]error{
		ErrorMalformedClientMessage: errors.New("[coniks] Malformed client request"),
		ErrorNameExisted:            errors.New("[coniks] Registering identity is already registered"),
		ErrorInternalServer:         errors.New("[coniks] Internal server error"),
	}
)

func (e ErrorCode) Error() error {
	if errorMessages[e] == nil {
		return errorMessages[ErrorInternalServer]
	}
	return errorMessages[e]
}
