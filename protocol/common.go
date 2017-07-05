package protocol

import (
	"encoding/hex"
	"fmt"

	"github.com/coniks-sys/coniks-go/crypto"
)

// ComputeDirectoryIdentity returns the hash of
// the directory's initial STR as a string.
// It panics if the STR isn't an initial STR (i.e. str.Epoch != 0).
func ComputeDirectoryIdentity(str *DirSTR) string {
	if str.Epoch != 0 {
		panic(fmt.Sprintf("[coniks] Expect epoch 0, got %x", str.Epoch))
	}
	return hex.EncodeToString(crypto.Digest(str.Signature))
}
