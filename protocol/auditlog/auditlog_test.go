package auditlog

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/auditor"
)

func TestInsertEmptyHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	NewTestAuditLog(t, 0)
}

func TestUpdateHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// update the directory so we can update the audit log
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	d.Update()
	h, _ := aud.get(dirInitHash)
	resp := protocol.NewSTRHistoryRange([]*protocol.DirSTR{d.LatestSTR()})

	err := h.Audit(resp)

	if err != nil {
		t.Fatal("Error auditing and updating the server history")
	}
}

func TestInsertPriorHistory(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	NewTestAuditLog(t, 10)
}

func TestInsertExistingHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	_, aud, hist := NewTestAuditLog(t, 0)

	// let's make sure that we can't re-insert a new server
	// history into our log
	err := aud.InitHistory("test-server", nil, hist)
	if err != protocol.ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when inserting an existing server history")
	}
}

func TestAuditLogBadEpochRange(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	d.Update()

	resp := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(0),
		EndEpoch:   uint64(1)})

	if resp.Error != protocol.ReqSuccess {
		t.Fatalf("Error occurred while fetching STR history: %s", resp.Error)
	}

	strs := resp.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(strs.STR) != 2 {
		t.Fatalf("Expect 2 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[0].Epoch != 0 || strs.STR[1].Epoch != 1 {
		t.Fatalf("Expect latest epoch of 1, got %d", strs.STR[1].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err := h.Audit(resp)
	if err != nil {
		t.Fatalf("Error occurred while auditing STR history: %s", err.Error())
	}

	// now try to audit the same range again: should fail because the
	// verified epoch is at 1
	err = h.Audit(resp)
	if err != protocol.CheckBadSTR {
		t.Fatalf("Expecting CheckBadSTR, got %s", err.Error())
	}
}

func TestGetLatestObservedSTR(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])

	res := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(d.LatestSTR().Epoch),
		EndEpoch:       uint64(d.LatestSTR().Epoch)})
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to get latest observed STR")
	}

	obs := res.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(obs.STR) == 0 {
		t.Fatal("Expect returned STR to be not nil")
	}
	if obs.STR[0].Epoch != d.LatestSTR().Epoch {
		t.Fatal("Unexpected epoch for returned latest STR")
	}
}

func TestGetObservedSTRInEpoch(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	_, aud, hist := NewTestAuditLog(t, 10)

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])

	res := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(8)})

	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to get latest range of STRs")
	}

	obs := res.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(obs.STR) == 0 {
		t.Fatal("Expect returned STR to be not nil")
	}
	if len(obs.STR) != 3 {
		t.Fatal("Expect 3 returned STRs")
	}
	if obs.STR[0].Epoch != 6 || obs.STR[2].Epoch != 8 {
		t.Fatal("Unexpected epoch for returned STRs")
	}
}

func TestGetObservedSTRMultipleEpochs(t *testing.T) {
	// create basic test directory and audit log with 2 STRs
	d, aud, hist := NewTestAuditLog(t, 1)

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])

	// first AuditingRequest
	res := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(0),
		EndEpoch:       d.LatestSTR().Epoch})

	if res.Error != protocol.ReqSuccess {
		t.Fatalf("Unable to get latest range of STRs, got %s", res.Error)
	}

	obs := res.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(obs.STR) != 2 {
		t.Fatal("Unexpected number of returned STRs")
	}
	if obs.STR[0].Epoch != 0 {
		t.Fatal("Unexpected initial epoch for returned STR range")
	}
	if obs.STR[1].Epoch != d.LatestSTR().Epoch {
		t.Fatal("Unexpected latest STR epoch for returned STR")
	}

	// go to next epoch
	d.Update()
	h, _ := aud.get(dirInitHash)
	resp := protocol.NewSTRHistoryRange([]*protocol.DirSTR{d.LatestSTR()})

	err := h.Audit(resp)
	if err != nil {
		t.Fatal("Error occurred updating audit log after auditing request")
	}

	// request the new latest STR
	res = aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     d.LatestSTR().Epoch,
		EndEpoch:       d.LatestSTR().Epoch})

	if res.Error != protocol.ReqSuccess {
		t.Fatal("Unable to get new latest STRs")
	}

	obs = res.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(obs.STR) != 1 {
		t.Fatal("Unexpected number of new latest STRs")
	}
	if obs.STR[0].Epoch != d.LatestSTR().Epoch {
		t.Fatal("Unexpected new latest STR epoch")
	}

}

func TestGetObservedSTRUnknown(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	d, aud, _ := NewTestAuditLog(t, 10)

	var unknown [crypto.HashSizeByte]byte
	res := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: unknown,
		StartEpoch:     uint64(d.LatestSTR().Epoch),
		EndEpoch:       uint64(d.LatestSTR().Epoch)})
	if res.Error != protocol.ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for latest STR")
	}

	res = aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: unknown,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(8)})
	if res.Error != protocol.ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for older STR")
	}

}

func TestGetObservedSTRMalformed(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	_, aud, hist := NewTestAuditLog(t, 10)

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])

	// also test the epoch range
	res := aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(4)})
	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect ErrMalformedMessage for bad end epoch")
	}
	res = aud.GetObservedSTRs(&protocol.AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(11)})
	if res.Error != protocol.ErrMalformedMessage {
		t.Fatal("Expect ErrMalformedMessage for out-of-bounds epoch range")
	}
}

func TestVerifyHashChainBadPrevSTRHash(t *testing.T) {
	// create basic test directory and audit log with 4 STRs
	d, aud, hist := NewTestAuditLog(t, 3)

	d.Update()

	// modify the latest STR so that the consistency check fails
	str := d.LatestSTR()
	str2 := *str.SignedTreeRoot
	str2.PreviousSTRHash = append([]byte{}, str.PreviousSTRHash...)
	str2.PreviousSTRHash[0]++
	str.SignedTreeRoot = &str2

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// try to verify a new STR with a bad previous STR hash:
	// case hash(verifiedSTR.Signature) != str.PreviousSTRHash in
	// str.VerifyHashChain()
	if str.VerifyHashChain(h.VerifiedSTR()) {
		t.Fatal("Expect hash chain verification to fail with bad previos STR hash")
	}
}

func TestVerifyHashChainBadPrevEpoch(t *testing.T) {
	// create basic test directory and audit log with 4 STRs
	d, aud, hist := NewTestAuditLog(t, 3)

	d.Update()

	// modify the latest STR so that the consistency check fails
	str := d.LatestSTR()
	str2 := *str.SignedTreeRoot
	str2.PreviousEpoch++
	str.SignedTreeRoot = &str2

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// try to verify a new STR with a bad previous STR hash:
	// case str.PrevousEpoch != verifiedSTR.Epoch in
	// str.VerifyHashChain()
	if str.VerifyHashChain(h.VerifiedSTR()) {
		t.Fatal("Expect hash chain verification to fail with bad previos epoch")
	}
}

func TestVerifyHashChainBadCurEpoch(t *testing.T) {
	// create basic test directory and audit log with 4 STRs
	d, aud, hist := NewTestAuditLog(t, 3)

	d.Update()

	// modify the latest STR so that the consistency check fails
	str := d.LatestSTR()
	str2 := *str.SignedTreeRoot
	str2.Epoch++
	str.SignedTreeRoot = &str2

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// try to verify a new STR with a bad previous STR hash:
	// case str.Epoch != verifiedSTR.Epoch+1 in
	// str.VerifyHashChain()
	if str.VerifyHashChain(h.VerifiedSTR()) {
		t.Fatal("Expect hash chain verification to fail with bad previos epoch")
	}
}

func TestSTRHistoryRequestLatest(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	d.Update()
	resp := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(d.LatestSTR().Epoch),
		EndEpoch:   uint64(d.LatestSTR().Epoch)})

	if resp.Error != protocol.ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", resp.Error)
	}

	str := resp.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(str.STR) != 1 {
		t.Fatalf("Expected 1 STR from directory, got %d", len(str.STR))
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err := h.Audit(resp)
	if err != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err.Error())
	}
}

func TestSTRHistoryRequestRangeLatest(t *testing.T) {
	// create basic test directory and audit log with 4 STR
	d, aud, hist := NewTestAuditLog(t, 3)

	// now update the directory 4 times and get a range
	for i := 0; i < 4; i++ {
		d.Update()
	}

	resp := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(d.LatestSTR().Epoch)})

	if resp.Error != protocol.ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", resp.Error)
	}

	strs := resp.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(strs.STR) != 4 {
		t.Fatalf("Expect 4 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[3].Epoch != 7 {
		t.Fatalf("Expect latest epoch of 7, got %d", strs.STR[3].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err := h.Audit(resp)
	if err != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err.Error())
	}
}

func TestSTRHistoryRequestInEpoch(t *testing.T) {
	// create basic test directory and audit log with 4 STR
	d, aud, hist := NewTestAuditLog(t, 3)

	// now update the directory 4 times and get a range
	for i := 0; i < 4; i++ {
		d.Update()
	}

	resp := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(4),
		EndEpoch:   uint64(5)})

	if resp.Error != protocol.ReqSuccess {
		t.Fatalf("Error occurred getting the latest STR from the directory: %s", resp.Error)
	}

	strs := resp.DirectoryResponse.(*protocol.STRHistoryRange)
	if len(strs.STR) != 2 {
		t.Fatalf("Expect 2 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[0].Epoch != 4 || strs.STR[1].Epoch != 5 {
		t.Fatalf("Expect latest epoch of 5, got %d", strs.STR[1].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := auditor.ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err := h.Audit(resp)
	if err != nil {
		t.Fatalf("Error occurred auditing the latest STR: %s", err.Error())
	}
}
