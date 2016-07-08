package protocol

// Defines constants representing the types
// of messages exchanged by clients and servers.
const (
	RegistrationType = 0
)

type Request struct {
	Type    int
	Request interface{}
}

type RegistrationRequest struct {
	Username               string `json:"username"`
	Key                    string `json:"key"`
	AllowUnsignedKeychange bool   `json:"allow_unsigned_key_change,omitempty"`
	AllowPublicLookup      bool   `json:"allow_public_lookup,omitempty"`
}

type Response interface{}

type ErrorResponse struct {
	Error int
}

type RegistrationResponse struct {
	STR string `json:"str"`
	AP  string `json:"ap"`
	TB  string `json:"tb"`
}

func NewErrorResponse(errCode int) *ErrorResponse {
	return &ErrorResponse{Error: errCode}
}
