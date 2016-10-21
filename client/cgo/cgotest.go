package main

/*
struct cgoVerify_return {
    int r0;
    int r1;
};
extern struct cgoVerify_return cgoVerify(int p0, char* p1, int p2, void* p3,
    int p4, long long unsigned int p5, void* p6, int p7, void* p8, int p9,
    char* p10, int p11);

struct cgoVerify_return testVerify(int type,
    char *uname, int unameSize,
    unsigned char *key, int keySize,
    long long unsigned int currentEpoch,
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
	v := C.testVerify(protocol.RegistrationType,
		byteSliceToCcharPtr([]byte(uname)), C.int(len(uname)),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response)))

	r0 := C.struct_cgoVerify_return(v).r0
	r1 := C.struct_cgoVerify_return(v).r1
	if r0 != C.int(protocol.Success) || r1 != C.int(protocol.PassedWithAProofOfAbsence) {
		t.Errorf("%s, %s\n", protocol.ErrorCode(r0).Error(), protocol.ErrorCode(r1).Error())
	}
	savedSTR = res.DirectoryResponse.(*protocol.DirectoryProof).STR.Signature

	d.Update()
	res, _ = d.KeyLookup(&protocol.KeyLookupRequest{uname})
	response, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}

	v = C.testVerify(protocol.KeyLookupType,
		byteSliceToCcharPtr([]byte(uname)), C.int(len(uname)),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response)))
	r0 = C.struct_cgoVerify_return(v).r0
	r1 = C.struct_cgoVerify_return(v).r1
	if r0 != C.int(protocol.Success) || r1 != C.int(protocol.PassedWithAProofOfAbsence) {
		t.Errorf("%s, %s\n", protocol.ErrorCode(r0).Error(), protocol.ErrorCode(r1).Error())
	}

	res, _ = d.KeyLookup(&protocol.KeyLookupRequest{"bob"})
	response, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	v = C.testVerify(protocol.KeyLookupType,
		byteSliceToCcharPtr([]byte("bob")), C.int(len("bob")),
		byteSliceToCucharPtr([]byte(key)), C.int(len(key)),
		0,
		byteSliceToCucharPtr(savedSTR), C.int(len(savedSTR)),
		byteSliceToCucharPtr(pk), C.int(len(pk)),
		byteSliceToCcharPtr(response), C.int(len(response)))
	r0 = C.struct_cgoVerify_return(v).r0
	r1 = C.struct_cgoVerify_return(v).r1
	if r0 != C.int(protocol.ErrorNameNotFound) || r1 != C.int(protocol.PassedWithAProofOfAbsence) {
		t.Errorf("%s, %s\n", protocol.ErrorCode(r0).Error(), protocol.ErrorCode(r1).Error())
	}
}
