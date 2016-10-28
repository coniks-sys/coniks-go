package protocol

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

func TestRegisterWithTB(t *testing.T) {
	// expect return a proof of absence
	// along with a TB of registering user
	d, _ := NewTestDirectory(t, true)

	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != Success {
		t.Fatal("Unable to register")
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
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
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != Success {
		t.Fatal("Unable to register")
	}
	// register in the same epoch
	// expect return a proof of absence
	// along with a TB of registering user
	// and error ErrorNameExisted
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}

	d.Update()
	// register in different epochs
	// expect return a proof of inclusion
	// and error ErrorNameExisted
	res, err = d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df = res.DirectoryResponse.(*DirectoryProof)
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
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
	res, _ := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	tb := res.DirectoryResponse.(*DirectoryProof).TB
	// lookup in the same epoch
	// expect a proof of absence and the TB of looking up user
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df := res.DirectoryResponse.(*DirectoryProof)
	if res.Error != Success {
		t.Fatal("Expect no error", "got", res.Error)
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
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
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df = res.DirectoryResponse.(*DirectoryProof)
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestDirectoryMonitoring(t *testing.T) {
	N := 10

	d, _ := NewTestDirectory(t, true)
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})

	d.Update()
	savedSTR := d.LatestSTR().Signature
	for i := 2; i < N; i++ {
		d.Update()
	}

	// missed from epoch 2
	res, err := d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch})
	df := res.DirectoryResponse.(*DirectoryProofs)
	if err != Success {
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
		savedSTR = str.Signature
	}

	// assert the number of STRs returned is correct
	res, err = d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch + 5})
	df = res.DirectoryResponse.(*DirectoryProofs)
	if err != Success {
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

	// lookup at epoch 1, expect a proof of absence & ErrorNameNotFound
	res, err := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(1)})
	df := res.DirectoryResponse.(*DirectoryProofs)
	if err != ErrorNameNotFound {
		t.Fatal("Expect error", ErrorNameNotFound, "got", err)
	}
	if len(df.AP) != 1 {
		t.Fatal("Expect only 1 auth path in response")
	}
	if len(df.STR) != int(d.LatestSTR().Epoch) {
		t.Fatal("Expect", d.LatestSTR().Epoch, "STRs", "got", len(df.STR))
	}

	d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	for i := 0; i < N; i++ {
		d.Update()
	}

	res, err = d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(5)})
	df = res.DirectoryResponse.(*DirectoryProofs)
	if err != Success {
		t.Fatal("Expect error", Success, "got", err)
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
	// Expect ErrorMalformedClientMessage
	_, err := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(6)})
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}
}

func TestMonitoringBadStartEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, true)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid MonitoringRequest (startEpoch > d.LatestEpoch())
	// Expect ErrorMalformedClientMessage
	_, err := d.Monitor(&MonitoringRequest{"alice", uint64(6), uint64(10)})
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}

	// Send an invalid MonitoringRequest (startEpoch > EndEpoch)
	// Expect ErrorMalformedClientMessage
	_, err = d.Monitor(&MonitoringRequest{"alice", uint64(2), uint64(0)})
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}
}

func TestPoliciesChanges(t *testing.T) {
	d, _ := NewTestDirectory(t, true)
	if p := d.LatestSTR().Policies.EpochDeadline; p != 1 {
		t.Fatal("Unexpected policies", "want", 1, "got", p)
	}

	// change the policies
	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	d.SetPolicies(2, vrfKey)
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
	p0 := d.pad.GetSTR(0).Policies.EpochDeadline
	p1 := d.pad.GetSTR(1).Policies.EpochDeadline
	p2 := d.pad.GetSTR(2).Policies.EpochDeadline
	if p0 != 1 || p1 != 1 || p2 != 2 {
		t.Fatal("Maybe the STR's policies were malformed")
	}
}
