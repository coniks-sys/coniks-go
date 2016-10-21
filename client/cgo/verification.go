package main

import "C"

import (
	"unsafe"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
)

// main is required to build a shared library, but does nothing
func main() {}

//export cgoVerify
// This cgoVerify returns 2 error codes,
// the first one is the error of the response,
// the second one is the error of the verification.
// If the response error is in ErrorResponses,
// the verification error will be ErrorCouldNotVerify.
func cgoVerify(cType C.int,
	cUname *C.char, cUnameSize C.int,
	cKey unsafe.Pointer, cKeySize C.int,
	cCurrentEpoch C.ulonglong,
	cSavedSTR unsafe.Pointer, cStrSize C.int,
	cPk unsafe.Pointer, cPkSize C.int,
	cResponse *C.char, cResponseSize C.int) (C.int, C.int) {

	if int(cUnameSize) == 0 ||
		int(cKeySize) == 0 ||
		(int(cStrSize) != sign.SignatureSize && int(cStrSize) != 0) ||
		int(cPkSize) != sign.PublicKeySize ||
		int(cResponseSize) == 0 {
		return C.int(protocol.ErrorMalformedDirectoryMessage),
			C.int(protocol.ErrorCouldNotVerify)
	}

	// uname := C.GoStringN(cUname, cUnameSize)
	// key := C.GoBytes(cKey, cKeySize)
	// savedSTR := C.GoBytes(cSavedSTR, cStrSize)
	// signKey := C.GoBytes(cPk, cPkSize)
	// currentEp := uint64(cCurrentEpoch)
	response := C.GoStringN(cResponse, cResponseSize)

	// TODO: fix me
	_, err := client.UnmarshalResponse(int(cType), []byte(response))
	if protocol.ErrorResponses[err] {
		return C.int(err), C.int(protocol.ErrorCouldNotVerify)
	}
	return C.int(err), C.int(protocol.PassedWithAProofOfAbsence)
}
