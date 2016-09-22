package main

/*
int testVerify(int type,
	char *uname, int unameSize,
	unsigned char *key, int keySize,
	unsigned long long currentEpoch,
	unsigned char *savedSTR, int strSize,
	unsigned char *pk, int pkSize,
	char *response, int responseSize) {
	return cgoVerify(type,
		uname, unameSize,
		key, keySize,
		currentEpoch,
		savedSTR, strSize,
		pk, pkSize, response, responseSize);
}

#cgo CFLAGS: -Wno-implicit-function-declaration
*/
import "C"
import (
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/coniks-sys/coniks-go/protocol"
)

func byteSliceToCucharPtr(buf []byte) *C.uchar {
	ptr := unsafe.Pointer(&buf[0])
	return (*C.uchar)(ptr)
}

func byteSliceToCcharPtr(buf []byte) *C.char {
	ptr := unsafe.Pointer(&buf[0])
	return (*C.char)(ptr)
}

func testVerify(t *testing.T) {
	uname := "alice"
	key := []byte("key")
	d, pk := protocol.NewTestDirectory(t, true)
	res, _ := d.Register(&protocol.RegistrationRequest{
		Username: uname,
		Key:      key})
	response, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	savedSTR := d.LatestSTR().Signature

	if v := C.testVerify(protocol.RegistrationType,
		byteSliceToCcharPtr([]byte(uname)), C.int(len(uname)),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response))); v != C.int(protocol.Passed) {
		t.Error(protocol.ErrorCode(v).Error())
	}
	savedSTR = res.DirectoryResponse.(*protocol.DirectoryProof).STR.Signature

	d.Update()
	res, _ = d.KeyLookup(&protocol.KeyLookupRequest{uname})
	response, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if v := C.testVerify(protocol.KeyLookupType,
		byteSliceToCcharPtr([]byte(uname)), C.int(len(uname)),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response))); v != C.int(protocol.Passed) {
		t.Error(protocol.ErrorCode(v).Error())
	}

	res, _ = d.KeyLookup(&protocol.KeyLookupRequest{"bob"})
	response, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if v := C.testVerify(protocol.KeyLookupType,
		byteSliceToCcharPtr([]byte(uname)), C.int(len(uname)),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response))); v != C.int(protocol.ErrorNameNotFound) {
		t.Error(protocol.ErrorCode(v).Error())
	}
}
