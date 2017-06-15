package auditor

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/protocol"
)

// ComputeDirectoryIdentity returns the hash of
// the directory's initial STR as a byte array.
// It panics if the STR isn't an initial STR (i.e. str.Epoch != 0).
func ComputeDirectoryIdentity(str *protocol.DirSTR) [crypto.HashSizeByte]byte {
	if str.Epoch != 0 {
		panic(fmt.Sprintf("[coniks] Expect epoch 0, got %x", str.Epoch))
	}

	var initSTRHash [crypto.HashSizeByte]byte
	copy(initSTRHash[:], crypto.Digest(str.Signature))
	return initSTRHash
}
