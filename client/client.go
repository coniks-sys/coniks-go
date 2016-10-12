package client

import (
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
)

// TODO:
// 1. return type of proof (inclusion of absence)
// 2. the client should know beforehand whether it expects tb to be nil or not
func Verify(requestType int, response []byte,
	uname string, key []byte,
	curEp uint64, savedSTR []byte, signKey sign.PublicKey) []protocol.ErrorCode {
	_, err := UnmarshalResponse(requestType, response)
	if protocol.ErrorResponses[err] {
		return []protocol.ErrorCode{err, protocol.ErrorCouldNotVerify}
	}
	return []protocol.ErrorCode{err, protocol.Passed}
}
