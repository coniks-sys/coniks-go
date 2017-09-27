package directory

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
)

func TestRegisterWithTB(t *testing.T) {
	// expect return a proof of absence
	// along with a TB of registering user
	d, _ := NewTestDirectory(t, true)

	res := d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to register")
	}
	if ap := df.AP[0]; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}
	if d.tbs["alice"] == nil {
		t.Fatal("Expect TBs array has registering user")
	}
	d.Update()
	if len(d.tbs) != 0 {
		t.Fatal("Expect TBs array is empty")
	}
}

func TestRegisterExistedUserWithTB(t *testing.T) {
	d, _ := NewTestDirectory(t, true)
	res := d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to register")
	}
	// register in the same epoch
	// expect return a proof of absence
	// along with a TB of registering user
	// and error ReqNameExisted
	res = d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqNameExisted {
		t.Fatal("Expect error code", protocol.ReqNameExisted, "got", res.Error)
	}
	if ap := df.AP[0]; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}

	d.Update()
	// register in different epochs
	// expect return a proof of inclusion
	// and error ReqNameExisted
	res = d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df = res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqNameExisted {
		t.Fatal("Expect error code", protocol.ReqNameExisted, "got", res.Error)
	}
	if ap := df.AP[0]; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestNewDirectoryPanicWithoutTB(t *testing.T) {
	// workaround for #110
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	NewTestDirectory(t, false)
}

func TestKeyLookupWithTB(t *testing.T) {
	d, _ := NewTestDirectory(t, true)
	res := d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	tb := res.DirectoryResponse.(*protocol.DirectoryProof).TB
	// lookup in the same epoch
	// expect a proof of absence and the TB of looking up user
	res = d.KeyLookup(&protocol.KeyLookupRequest{Username: "alice"})
	df := res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Expect no error", "got", res.Error)
	}
	if ap := df.AP[0]; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil || !bytes.Equal(df.TB.Value, []byte("key")) {
		t.Fatal("Expect the TB of looking up user")
	}
	// assert that the server returns the same TB
	if !bytes.Equal(df.TB.Signature, tb.Signature) ||
		!bytes.Equal(df.TB.Index, tb.Index) ||
		!bytes.Equal(df.TB.Value, tb.Value) {
		t.Fatal("Expect the same TB for the registration and lookup")
	}

	d.Update()
	// lookup in epoch after registering epoch
	// expect a proof of inclusion
	res = d.KeyLookup(&protocol.KeyLookupRequest{Username: "alice"})
	df = res.DirectoryResponse.(*protocol.DirectoryProof)
	if ap := df.AP[0]; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestDirectoryMonitoring(t *testing.T) {
	N := 10

	d, _ := NewTestDirectory(t, true)
	d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})

	d.Update()
	savedSTR := d.LatestSTR()
	for i := 2; i < N; i++ {
		d.Update()
	}

	// missed from epoch 2
	res := d.Monitor(&protocol.MonitoringRequest{
		Username: "alice", StartEpoch: uint64(2), EndEpoch: d.LatestSTR().Epoch,
	})
	df := res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to perform key lookup in epoch", 2)
	}
	expectNumberOfSTR := 10 - 2
	if len(df.AP) != expectNumberOfSTR || len(df.STR) != expectNumberOfSTR {
		t.Fatal("Expect", expectNumberOfSTR, "auth paths/STRs", "got", len(df.AP), "auth paths and", len(df.STR), "STRs")
	}

	for i := 0; i < expectNumberOfSTR; i++ {
		str := df.STR[i]
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Hash chain does not verify at epoch", i)
		}
		// we can ignore the auth path verification
		// since it is already tested in merkletree package
		savedSTR = str
	}

	// assert the number of STRs returned is correct
	res = d.Monitor(&protocol.MonitoringRequest{
		Username: "alice", StartEpoch: uint64(2), EndEpoch: d.LatestSTR().Epoch + 5,
	})
	df = res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to perform key lookup in epoch", 2)
	}
	if len(df.AP) != expectNumberOfSTR || len(df.STR) != expectNumberOfSTR {
		t.Fatal("Expect", expectNumberOfSTR, "auth paths/STRs", "got", len(df.AP), "auth paths and", len(df.STR), "STRs")
	}
}

func TestDirectoryKeyLookupInEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, true)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// lookup at epoch 1, expect a proof of absence & ReqNameNotFound
	res := d.KeyLookupInEpoch(&protocol.KeyLookupInEpochRequest{Username: "alice", Epoch: uint64(1)})
	df := res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqNameNotFound {
		t.Fatal("Expect error", protocol.ReqNameNotFound, "got", res.Error)
	}
	if len(df.AP) != 1 {
		t.Fatal("Expect only 1 auth path in response")
	}
	if len(df.STR) != int(d.LatestSTR().Epoch) {
		t.Fatal("Expect", d.LatestSTR().Epoch, "STRs", "got", len(df.STR))
	}

	d.Register(&protocol.RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	for i := 0; i < N; i++ {
		d.Update()
	}

	res = d.KeyLookupInEpoch(&protocol.KeyLookupInEpochRequest{Username: "alice", Epoch: uint64(5)})
	df = res.DirectoryResponse.(*protocol.DirectoryProof)
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Expect error", protocol.ReqSuccess, "got", res.Error)
	}
	if len(df.AP) != 1 {
		t.Fatal("Expect only 1 auth path in response")
	}
	if len(df.STR) != 2 {
		t.Fatal("Expect", 2, "STRs", "got", len(df.STR))
	}
}

func TestDirectoryKeyLookupInEpochBadEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, true)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid KeyLookupInEpochRequest (epoch > d.LatestEpoch())
	// Expect ErrMalformedMessage
	res := d.KeyLookupInEpoch(&protocol.KeyLookupInEpochRequest{Username: "alice", Epoch: uint64(6)})
	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect error", protocol.ErrMalformedMessage, "got", res.Error)
	}
}

func TestMonitoringBadStartEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, true)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid MonitoringRequest (startEpoch > d.LatestEpoch())
	// Expect ErrMalformedMessage
	res := d.Monitor(&protocol.MonitoringRequest{
		Username: "alice", StartEpoch: uint64(6), EndEpoch: uint64(10),
	})
	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect error", protocol.ErrMalformedMessage, "got", res.Error)
	}

	// Send an invalid MonitoringRequest (startEpoch > EndEpoch)
	// Expect ErrMalformedMessage
	res = d.Monitor(&protocol.MonitoringRequest{
		Username: "alice", StartEpoch: uint64(2), EndEpoch: uint64(0),
	})
	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect error", protocol.ErrMalformedMessage, "got", res.Error)
	}
}

func TestPoliciesChanges(t *testing.T) {
	d, _ := NewTestDirectory(t, true)
	if p := d.LatestSTR().Policies.EpochDeadline; p != 1 {
		t.Fatal("Unexpected policies", "want", 1, "got", p)
	}

	// change the policies
	d.SetPolicies(2)
	d.Update()
	// expect the policies doesn't change yet
	if p := d.LatestSTR().Policies.EpochDeadline; p != 1 {
		t.Fatal("Unexpected policies", "want", 1, "got", p)
	}

	d.Update()
	// expect the new policies
	if p := d.LatestSTR().Policies.EpochDeadline; p != 2 {
		t.Fatal("Unexpected policies", "want", 2, "got", p)
	}
	p0 := protocol.GetPolicies(d.pad.GetSTR(0)).EpochDeadline
	p1 := protocol.GetPolicies(d.pad.GetSTR(1)).EpochDeadline
	p2 := protocol.GetPolicies(d.pad.GetSTR(2)).EpochDeadline
	if p0 != 1 || p1 != 1 || p2 != 2 {
		t.Fatal("Maybe the STR's policies were malformed")
	}
}

func TestSTRHistoryRequestBadRange(t *testing.T) {
	// create basic test directory
	d, _ := NewTestDirectory(t, true)

	d.Update()

	res := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(2)})

	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect ErrMalformedMessage for bad STR history end epoch")
	}

	res = d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(6),
		EndEpoch:   uint64(d.LatestSTR().Epoch)})

	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect ErrMalformedMessage for out-of-bounds STR history")
	}
}
