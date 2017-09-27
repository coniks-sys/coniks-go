package client

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

var (
	alice = "alice"
	bob   = "bob"
	key   = []byte("key")
)

func registerAndVerify(d *directory.ConiksDirectory, cc *ConsistencyChecks,
	name string, key []byte) error {
	request := &protocol.RegistrationRequest{
		Username: name,
		Key:      key,
	}
	res := d.Register(request)
	return cc.HandleResponse(protocol.RegistrationType, res, name, key)
}

func lookupAndVerify(d *directory.ConiksDirectory, cc *ConsistencyChecks,
	name string, key []byte) error {
	request := &protocol.KeyLookupRequest{
		Username: name,
	}
	res := d.KeyLookup(request)
	return cc.HandleResponse(protocol.KeyLookupType, res, name, key)
}

func TestMalformedClientMessage(t *testing.T) {
	d, pk := directory.NewTestDirectory(t, true)
	cc := New(d.LatestSTR(), true, pk)

	request := &protocol.RegistrationRequest{
		Username: "", // invalid username
		Key:      key,
	}
	res := d.Register(request)
	if err := cc.HandleResponse(protocol.RegistrationType, res, "", key); err != protocol.ErrMalformedMessage {
		t.Error("Unexpected verification result",
			"got", err)
	}
}

func TestMalformedDirectoryMessage(t *testing.T) {
	d, pk := directory.NewTestDirectory(t, true)
	cc := New(d.LatestSTR(), true, pk)

	request := &protocol.RegistrationRequest{
		Username: "alice",
		Key:      key,
	}
	res := d.Register(request)
	// modify response message
	res.DirectoryResponse.(*protocol.DirectoryProof).STR = nil
	if err := cc.HandleResponse(protocol.RegistrationType, res, "alice", key); err != protocol.ErrMalformedMessage {
		t.Error("Unexpected verification result")
	}
}

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := directory.NewTestDirectory(t, true)

	cc := New(d.LatestSTR(), true, pk)

	if err := registerAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// test error name existed
	if err := registerAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}

	// test error name existed with different key
	if err := registerAndVerify(d, cc, alice, []byte{1, 2, 3}); err != protocol.CheckBindingsDiffer {
		t.Error(err)
	}
	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// re-register in a different epoch
	// Since the fulfilled promise verification would be perform
	// when the client is monitoring, we do _not_ expect a TB's verification here.
	d.Update()

	if err := registerAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}
	if err := registerAndVerify(d, cc, alice, []byte{1, 2, 3}); err != protocol.CheckBindingsDiffer {
		t.Error(err)
	}
}

func TestVerifyFullfilledPromise(t *testing.T) {
	d, pk := directory.NewTestDirectory(t, true)

	cc := New(d.LatestSTR(), true, pk)

	if err := registerAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}
	if err := registerAndVerify(d, cc, bob, key); err != nil {
		t.Error(err)
	}

	if len(cc.TBs) != 2 {
		t.Fatal("Expect the directory to return signed promises")
	}

	d.Update()

	for i := 0; i < 2; i++ {
		if err := lookupAndVerify(d, cc, alice, key); err != nil {
			t.Error(err)
		}
	}

	// should contain the TBs of bob
	if len(cc.TBs) != 1 || cc.TBs[bob] == nil {
		t.Error("Expect the directory to insert the binding as promised")
	}

	if err := lookupAndVerify(d, cc, bob, key); err != nil {
		t.Error(err)
	}
	if len(cc.TBs) != 0 {
		t.Error("Expect the directory to insert the binding as promised")
	}
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := directory.NewTestDirectory(t, true)

	cc := New(d.LatestSTR(), true, pk)

	// do lookup first
	if err := lookupAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}

	// register
	if err := registerAndVerify(d, cc, alice, key); err != nil {
		t.Error(err)
	}

	// do lookup in the same epoch - TB TOFU
	// and get the key from the response. The key would be extracted from the TB
	request := &protocol.KeyLookupRequest{
		Username: alice,
	}
	res := d.KeyLookup(request)
	if res.Error != protocol.ReqSuccess {
		t.Error("Expect", protocol.ReqSuccess, "got", res.Error)
	}
	if err := cc.HandleResponse(protocol.KeyLookupType, res, alice, nil); err != nil {
		t.Error("Expect", nil, "got", err)
	}
	recvKey, e := res.GetKey()
	if e != nil && !bytes.Equal(recvKey, key) {
		t.Error("The directory has returned a wrong key.")
	}

	d.Update()

	// do lookup in the different epoch
	// this time, the key would be extracted from the AP.
	request = &protocol.KeyLookupRequest{
		Username: alice,
	}
	res = d.KeyLookup(request)
	if res.Error != protocol.ReqSuccess {
		t.Error("Expect", protocol.ReqSuccess, "got", res.Error)
	}
	if err := cc.HandleResponse(protocol.KeyLookupType, res, alice, nil); err != nil {
		t.Error("Expect nil", "got", err)
	}
	recvKey, e = res.GetKey()
	if e != nil && !bytes.Equal(recvKey, key) {
		t.Error("The directory has returned a wrong key.")
	}

	// test error name not found
	if err := lookupAndVerify(d, cc, bob, key); err != nil {
		t.Error(err)
	}
}
