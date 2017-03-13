package protocol

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/merkletree"
)

var (
	alice = "alice"
	bob   = "bob"
	key   = []byte("key")
)

func registerAndVerify(d *ConiksDirectory, cc *ConsistencyChecks,
	name string, key []byte) (error, error) {
	request := &RegistrationRequest{
		Username: name,
		Key:      key,
	}
	res, err := d.Register(request)
	return err, cc.HandleResponse(RegistrationType, res, name, key)
}

func lookupAndVerify(d *ConiksDirectory, cc *ConsistencyChecks,
	name string, key []byte) (error, error) {
	request := &KeyLookupRequest{
		Username: name,
	}
	res, err := d.KeyLookup(request)
	return err, cc.HandleResponse(KeyLookupType, res, name, key)
}

func monitorAndVerify(d *ConiksDirectory, cc *ConsistencyChecks,
	name string, key []byte, startEp, endEp uint64) (error, error) {
	request := &MonitoringRequest{
		Username:   name,
		StartEpoch: startEp,
		EndEpoch:   endEp,
	}
	res, err := d.Monitor(request)
	return err, cc.HandleResponse(MonitoringType, res, name, key)
}

func newTestVerifier(str *DirSTR, pk sign.PublicKey) *ConsistencyChecks {
	return NewCC(str, pk, nil, true, nil)
}

func TestVerifyWithError(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	str := d.LatestSTR()

	// modify the pinning STR so that the consistency check should fail.
	str2 := *str.SignedTreeRoot
	str2.Signature = append([]byte{}, str.Signature...)
	str2.Signature[0]++
	str.SignedTreeRoot = &str2

	cc := newTestVerifier(str, pk)

	e1, e2 := registerAndVerify(d, cc, alice, key)
	if e1 != ReqSuccess {
		t.Error("Expect", ReqSuccess, "got", e1)
	}
	if e2 != CheckBadSTR {
		t.Error("Expect", CheckBadSTR, "got", e2)
	}
}

func TestMalformedClientMessage(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	request := &RegistrationRequest{
		Username: "", // invalid username
		Key:      key,
	}
	res, _ := d.Register(request)
	if err := cc.HandleResponse(RegistrationType, res, "", key); err != ErrMalformedClientMessage {
		t.Error("Unexpected verification result")
	}
}

func TestMalformedDirectoryMessage(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	request := &RegistrationRequest{
		Username: "alice",
		Key:      key,
	}
	res, _ := d.Register(request)
	// modify response message
	res.DirectoryResponse.(*DirectoryProof).STR = nil
	if err := cc.HandleResponse(RegistrationType, res, "alice", key); err != ErrMalformedDirectoryMessage {
		t.Error("Unexpected verification result")
	}
}

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	if e1, e2 := registerAndVerify(d, cc, alice, key); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// test error name existed
	if e1, e2 := registerAndVerify(d, cc, alice, key); e1 != ReqNameExisted || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	// test error name existed with different key
	if e1, e2 := registerAndVerify(d, cc, alice, []byte{1, 2, 3}); e1 != ReqNameExisted || e2 != CheckBindingsDiffer {
		t.Error(e1)
		t.Error(e2)
	}
	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// re-register in a different epoch
	// Since the fulfilled promise verification would be perform
	// when the client is monitoring, we do _not_ expect a TB's verification here.
	d.Update()

	if e1, e2 := registerAndVerify(d, cc, alice, key); e1 != ReqNameExisted || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}
	if e1, e2 := registerAndVerify(d, cc, alice, []byte{1, 2, 3}); e1 != ReqNameExisted || e2 != CheckBindingsDiffer {
		t.Error(e1)
		t.Error(e2)
	}
}

func TestVerifyFullfilledPromise(t *testing.T) {
	N := 3
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	if e1, e2 := registerAndVerify(d, cc, alice, key); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return signed promises")
	}

	for i := 0; i < N; i++ {
		d.Update()
	}

	if e1, e2 := monitorAndVerify(d, cc, alice, key, cc.SavedSTR.Epoch+1, d.LatestSTR().Epoch); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	if len(cc.TBs) != 0 {
		t.Error("Expect the directory to insert the binding as promised")
	}
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	// do lookup first
	if e1, e2 := lookupAndVerify(d, cc, alice, key); e1 != ReqNameNotFound || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	// register
	if e1, e2 := registerAndVerify(d, cc, alice, key); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}

	// do lookup in the same epoch - TB TOFU
	// and get the key from the response. The key would be extracted from the TB
	request := &KeyLookupRequest{
		Username: alice,
	}
	res, err := d.KeyLookup(request)
	if err != ReqSuccess {
		t.Error("Expect", ReqSuccess, "got", err)
	}
	if err := cc.HandleResponse(KeyLookupType, res, alice, nil); err != CheckPassed {
		t.Error("Expect", CheckPassed, "got", err)
	}
	recvKey, e := res.GetKey()
	if e != nil && !bytes.Equal(recvKey, key) {
		t.Error("The directory has returned a wrong key.")
	}

	d.Update()

	// do lookup in the different epoch
	// this time, the key would be extracted from the AP.
	request = &KeyLookupRequest{
		Username: alice,
	}
	res, err = d.KeyLookup(request)
	if err != ReqSuccess {
		t.Error("Expect", ReqSuccess, "got", err)
	}
	if err := cc.HandleResponse(KeyLookupType, res, alice, nil); err != CheckPassed {
		t.Error("Expect", CheckPassed, "got", err)
	}
	recvKey, e = res.GetKey()
	if e != nil && !bytes.Equal(recvKey, key) {
		t.Error("The directory has returned a wrong key.")
	}

	// test error name not found
	if e1, e2 := lookupAndVerify(d, cc, bob, key); e1 != ReqNameNotFound || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}
}

func TestVerifyMonitoring(t *testing.T) {
	N := 5
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	registerAndVerify(d, cc, alice, key)

	// monitor binding was inserted
	d.Update()

	if e1, e2 := monitorAndVerify(d, cc, alice, key, cc.SavedSTR.Epoch+1, d.LatestSTR().Epoch); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}
	for i := 0; i < N; i++ {
		d.Update()
	}
	if e1, e2 := monitorAndVerify(d, cc, alice, key, cc.SavedSTR.Epoch+1, d.LatestSTR().Epoch); e1 != ReqSuccess || e2 != CheckPassed {
		t.Error(e1)
		t.Error(e2)
	}
}

// Expect the ConsistencyChecks to return CheckUnexpectedMonitoringEpoch:
// - If: StartEpoch > SavedEpoch + 1
func TestVerifyMonitoringBadEpoch(t *testing.T) {
	N := 5
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	registerAndVerify(d, cc, alice, key)

	for i := 0; i < N; i++ {
		d.Update()
	}

	if e1, e2 := monitorAndVerify(d, cc, alice, nil, cc.SavedSTR.Epoch+2, d.LatestSTR().Epoch); e1 != ReqSuccess || e2 != CheckUnexpectedMonitoringEpoch {
		t.Error(e1)
		t.Error(e2)
	}
}

func TestMalformedMonitoringResponse(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	cc := newTestVerifier(d.LatestSTR(), pk)

	// len(AP) == 0
	malformedResponse := &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProofs{
			AP:  nil,
			STR: append([]*DirSTR{}, &DirSTR{}),
		},
	}
	if err := cc.HandleResponse(MonitoringType, malformedResponse, alice, key); err != ErrMalformedDirectoryMessage {
		t.Error(err)
	}

	// len(AP) != len(STR)
	str2 := append([]*DirSTR{}, &DirSTR{})
	str2 = append(str2, &DirSTR{})
	malformedResponse = &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProofs{
			AP:  append([]*merkletree.AuthenticationPath{}, &merkletree.AuthenticationPath{}),
			STR: str2,
		},
	}
	if err := cc.HandleResponse(MonitoringType, malformedResponse, alice, key); err != ErrMalformedDirectoryMessage {
		t.Error(err)
	}

	// len(STR) == 0
	malformedResponse = &Response{
		Error: ReqSuccess,
		DirectoryResponse: &DirectoryProofs{
			AP:  append([]*merkletree.AuthenticationPath{}, &merkletree.AuthenticationPath{}),
			STR: nil,
		},
	}
	if err := cc.HandleResponse(MonitoringType, malformedResponse, alice, key); err != ErrMalformedDirectoryMessage {
		t.Error(err)
	}

	// Error != ReqSuccess
	malformedResponse = &Response{
		Error: ReqNameNotFound,
		DirectoryResponse: &DirectoryProofs{
			AP:  append([]*merkletree.AuthenticationPath{}, &merkletree.AuthenticationPath{}),
			STR: nil,
		},
	}
	if err := cc.HandleResponse(MonitoringType, malformedResponse, alice, key); err != ErrMalformedDirectoryMessage {
		t.Error(err)
	}
}
