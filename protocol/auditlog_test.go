package protocol

import "testing"

func TestInsertEmptyHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	_, _, _ = NewTestAuditLog(t, 0)
}

func TestUpdateHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// update the directory so we can update the audit log
	dirInitHash := computeInitSTRHash(hist[0])
	d.Update()
	err := aud.Update(dirInitHash, d.LatestSTR())

	if err != nil {
		t.Fatal("Error updating the server history")
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
	err := aud.Insert("test-server", nil, hist)
	if err != ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when inserting an existing server history")
	}
}

func TestUpdateUnknownHistory(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, _ := NewTestAuditLog(t, 0)

	// let's make sure that we can't update a history for an unknown
	// directory in our log
	err := aud.Update("unknown", d.LatestSTR())
	if err != ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when updating an unknown server history")
	}
}

func TestUpdateBadNewSTR(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	d, aud, hist := NewTestAuditLog(t, 10)

	// compute the hash of the initial STR for later lookups
	dirInitHash := computeInitSTRHash(hist[0])

	// update the directory a few more times and then try
	// to update
	d.Update()
	d.Update()

	err := aud.Update(dirInitHash, d.LatestSTR())
	if err != CheckBadSTR {
		t.Fatal("Expected a CheckBadSTR when attempting update a server history with a bad STR")
	}
}

func TestGetLatestObservedSTR(t *testing.T) {
	// create basic test directory and audit log with 1 STR
	d, aud, hist := NewTestAuditLog(t, 0)

	// compute the hash of the initial STR for later lookups
	dirInitHash := computeInitSTRHash(hist[0])

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
	dirInitHash := computeInitSTRHash(hist[0])

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

func TestGetEntireObservedSTRHist(t *testing.T) {
	// create basic test directory and audit log with 2 STRs
	d, aud, hist := NewTestAuditLog(t, 1)

	// compute the hash of the initial STR for later lookups
	dirInitHash := computeInitSTRHash(hist[0])

	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: dirInitHash,
		StartEpoch:     uint64(0),
		EndEpoch:       d.LatestSTR().Epoch})

	if err != ReqSuccess {
		t.Fatal("Unable to get latest range of STRs")
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
}

func TestGetObservedSTRUnknown(t *testing.T) {
	// create basic test directory and audit log with 11 STRs
	d, aud, _ := NewTestAuditLog(t, 10)

	_, err := aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: "unknown",
		StartEpoch:     uint64(d.LatestSTR().Epoch),
		EndEpoch:       uint64(d.LatestSTR().Epoch)})
	if err != ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for latest STR")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirInitSTRHash: "unknown",
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
	dirInitHash := computeInitSTRHash(hist[0])

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
