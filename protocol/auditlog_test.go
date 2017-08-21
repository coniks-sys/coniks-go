package protocol

import (
	"github.com/coniks-sys/coniks-go/crypto"
	"testing"
)

func TestInsertEmptyHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	_, _, _ = NewTestAuditLog(t, 0)
}

func TestUpdateHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// update the directory so we can update the audit log
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	d.Update()
	h, _ := aud.get(dirInitHash)
	resp, _ := NewSTRHistoryRange([]*DirSTR{d.LatestSTR()})

	err := h.Audit(resp)

	if err != nil {
		t.Fatal("Error auditing and updating the server history")
	}
}

func TestInsertPriorHistory(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	_, _, _ = NewTestAuditLog(t, 10)
}

func TestInsertExistingHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	_, aud, hist := NewTestAuditLog(t, 0)

	// let's make sure that we can't re-insert a new server
	// history into our log
	err := aud.InitHistory("test-server", nil, hist)
	if err != ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when inserting an existing server history")
	}
}

func TestAuditLogBadEpochRange(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	d.Update()

	resp, err := d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(0),
		EndEpoch:   uint64(0)})

	if err != ReqSuccess {
		t.Fatalf("Error occurred while fetching STR history: %s", err.Error())
	}

	strs := resp.DirectoryResponse.(*STRHistoryRange)
	if len(strs.STR) != 2 {
		t.Fatalf("Expect 2 STRs from directory, got %d", len(strs.STR))
	}

	if strs.STR[0].Epoch != 0 || strs.STR[1].Epoch != 1 {
		t.Fatalf("Expect latest epoch of 1, got %d", strs.STR[1].Epoch)
	}

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	err1 := h.Audit(resp)
	if err1 != ErrMalformedDirectoryMessage {
		t.Fatalf("Expect ErrMalformedDirectoryMessage when auditing an STR range starting at 1")
	}
}

func TestGetLatestObservedSTR(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])

	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(d.LatestSTR().Epoch),
		EndEpoch:       uint64(d.LatestSTR().Epoch)})
	if err != ReqSuccess {
		t.Fatal("Unable to get latest observed STR")
	}

	obs := res.DirectoryResponse.(*STRHistoryRange)
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
	dirInitHash := ComputeDirectoryIdentity(hist[0])

	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(8)})

	if err != ReqSuccess {
		t.Fatal("Unable to get latest range of STRs")
	}

	obs := res.DirectoryResponse.(*STRHistoryRange)
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
	dirInitHash := ComputeDirectoryIdentity(hist[0])

	// first AuditingRequest
	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(0),
		EndEpoch:       d.LatestSTR().Epoch})

	if err != ReqSuccess {
		t.Fatalf("Unable to get latest range of STRs, got %s", err.Error())
	}

	obs := res.DirectoryResponse.(*STRHistoryRange)
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
	resp, _ := NewSTRHistoryRange([]*DirSTR{d.LatestSTR()})

	err1 := h.Audit(resp)
	if err1 != nil {
		t.Fatal("Error occurred updating audit log after auditing request")
	}

	// request the new latest STR
	res, err = aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     d.LatestSTR().Epoch,
		EndEpoch:       d.LatestSTR().Epoch})

	if err != ReqSuccess {
		t.Fatal("Unable to get new latest STRs")
	}

	obs = res.DirectoryResponse.(*STRHistoryRange)
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
	_, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: unknown,
		StartEpoch:     uint64(d.LatestSTR().Epoch),
		EndEpoch:       uint64(d.LatestSTR().Epoch)})
	if err != ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for latest STR")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: unknown,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(8)})
	if err != ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for older STR")
	}

}

func TestGetObservedSTRMalformed(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	_, aud, hist := NewTestAuditLog(t, 10)

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])

	// also test the epoch range
	_, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(4)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect ErrMalformedClientMessage for bad end epoch")
	}
	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(6),
		EndEpoch:       uint64(11)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect ErrMalformedClientMessage for out-of-bounds epoch range")
	}
}
