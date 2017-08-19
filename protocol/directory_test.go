package protocol

import (
	"bytes"
	"testing"
)

func TestRegisterWithTB(t *testing.T) {
	// expect return a proof of absence
	// along with a TB of registering user
	d, _ := NewTestDirectory(t, true)

	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != ReqSuccess {
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
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != ReqSuccess {
		t.Fatal("Unable to register")
	}
	// register in the same epoch
	// expect return a proof of absence
	// along with a TB of registering user
	// and error ReqNameExisted
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != ReqNameExisted {
		t.Fatal("Expect error code", ReqNameExisted, "got", err)
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
	res, err = d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df = res.DirectoryResponse.(*DirectoryProof)
	if err != ReqNameExisted {
		t.Fatal("Expect error code", ReqNameExisted, "got", err)
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
	res, _ := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	tb := res.DirectoryResponse.(*DirectoryProof).TB
	// lookup in the same epoch
	// expect a proof of absence and the TB of looking up user
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df := res.DirectoryResponse.(*DirectoryProof)
	if res.Error != ReqSuccess {
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
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df = res.DirectoryResponse.(*DirectoryProof)
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
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})

	d.Update()
	savedSTR := d.LatestSTR()
	for i := 2; i < N; i++ {
		d.Update()
	}

	// missed from epoch 2
	res, err := d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != ReqSuccess {
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
	res, err = d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch + 5})
	df = res.DirectoryResponse.(*DirectoryProof)
	if err != ReqSuccess {
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
	res, err := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(1)})
	df := res.DirectoryResponse.(*DirectoryProof)
	if err != ReqNameNotFound {
		t.Fatal("Expect error", ReqNameNotFound, "got", err)
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
	df = res.DirectoryResponse.(*DirectoryProof)
	if err != ReqSuccess {
		t.Fatal("Expect error", ReqSuccess, "got", err)
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
	// Expect ErrMalformedClientMessage
	_, err := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(6)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect error", ErrMalformedClientMessage, "got", err)
	}
}

func TestMonitoringBadStartEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, true)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid MonitoringRequest (startEpoch > d.LatestEpoch())
	// Expect ErrMalformedClientMessage
	_, err := d.Monitor(&MonitoringRequest{"alice", uint64(6), uint64(10)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect error", ErrMalformedClientMessage, "got", err)
	}

	// Send an invalid MonitoringRequest (startEpoch > EndEpoch)
	// Expect ErrMalformedClientMessage
	_, err = d.Monitor(&MonitoringRequest{"alice", uint64(2), uint64(0)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect error", ErrMalformedClientMessage, "got", err)
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
	p0 := GetPolicies(d.pad.GetSTR(0)).EpochDeadline
	p1 := GetPolicies(d.pad.GetSTR(1)).EpochDeadline
	p2 := GetPolicies(d.pad.GetSTR(2)).EpochDeadline
	if p0 != 1 || p1 != 1 || p2 != 2 {
		t.Fatal("Maybe the STR's policies were malformed")
	}
}

func TestSTRHistoryRequestLatest(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	d.Update()
	resp, err := d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(d.LatestSTR().Epoch),
		EndEpoch:   uint64(0)})

	if err != ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", err.Error())
	}

	str := resp.DirectoryResponse.(*STRHistoryRange)
	if len(str.STR) != 1 {
		t.Fatalf("Expected 1 STR from directory, got %d", len(str.STR))
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err1 := h.Audit(resp)
	if err1 != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err1.Error())
	}

}

func TestSTRHistoryRequestRangeLatest(t *testing.T) {
	// create basic test directory and audit log with 4 STR
	d, aud, hist := NewTestAuditLog(t, 3)

	// now update the directory 4 times and get a range
	for i := 0; i < 4; i++ {
		d.Update()
	}

	resp, err := d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(0)})

	if err != ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", err.Error())
	}

	strs := resp.DirectoryResponse.(*STRHistoryRange)
	if len(strs.STR) != 4 {
		t.Fatalf("Expect 4 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[3].Epoch != 7 {
		t.Fatalf("Expect latest epoch of 7, got %d", strs.STR[3].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err1 := h.Audit(resp)
	if err1 != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err1.Error())
	}

}

func TestSTRHistoryRequestInEpoch(t *testing.T) {
	// create basic test directory and audit log with 4 STR
	d, aud, hist := NewTestAuditLog(t, 3)

	// now update the directory 4 times and get a range
	for i := 0; i < 4; i++ {
		d.Update()
	}

	resp, err := d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(5)})

	if err != ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", err.Error())
	}

	strs := resp.DirectoryResponse.(*STRHistoryRange)
	if len(strs.STR) != 2 {
		t.Fatalf("Expect 2 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[0].Epoch != 4 || strs.STR[1].Epoch != 5 {
		t.Fatalf("Expect latest epoch of 5, got %d", strs.STR[1].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err1 := h.Audit(resp)
	if err1 != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err1.Error())
	}

}

func TestSTRHistoryRequestBadRange(t *testing.T) {
	// create basic test directory
	d, _ := NewTestDirectory(t, true)

	d.Update()

	_, err := d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(2)})

	if err != ErrMalformedAuditorMessage {
		t.Fatal("Expect ErrMalformedAuditorMessage for bad STR history end epoch")
	}

	_, err = d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(6),
		EndEpoch:   uint64(0)})

	if err != ErrMalformedAuditorMessage {
		t.Fatal("Expect ErrMalformedAuditorMessage for out-of-bounds STR history")
	}
}
