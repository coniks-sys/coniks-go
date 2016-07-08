// Defines constants representing the types
// of errors that the server may return to a client.

package protocol

import "errors"

const (
	Success                     = 10
	ErrorInternalServer         = 11
	ErrorNameExisted            = 12
	ErrorMalformedClientMessage = 14
)

var (
	errorMessages = map[int]error{
		ErrorMalformedClientMessage: errors.New("[coniks] Malformed client request"),
		ErrorNameExisted:            errors.New("[coniks] Registering identity is already registered"),
		ErrorInternalServer:         errors.New("[coniks] Internal server error"),
	}
)

func Error(errCode int) error {
	e := errorMessages[errCode]
	if e.Error() == "" {
		e = errorMessages[ErrorInternalServer]
	}
	return e
}
