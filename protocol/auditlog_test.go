package protocol

import (
	"testing"
)

func TestInsertEmptyHistory(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	err := aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history")
	}
}

func TestUpdateHistory(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	err := aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history")
	}

	// update the directory so we can update the audit log
	d.Update()
	err = aud.Update("test-server", d.LatestSTR())

	if err != nil {
		t.Fatal("Error updating the server history")
	}
}

func TestInsertPriorHistory(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	// create 10 epochs
	priorSTRs := make(map[uint64]*DirSTR)
	for i := 0; i < 10; i++ {
		priorSTRs[d.LatestSTR().Epoch] = d.LatestSTR()
		d.Update()
	}

	// now insert
	err := aud.Insert("test-server", pk, priorSTRs, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history with prior STRs")
	}
}

func TestInsertExistingHistory(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()
	err := aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history")
	}

	// let's make sure that we can't re-insert a new server
	// history into our log
	err = aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when inserting an existing server history")
	}
}

func TestUpdateUnknownHistory(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()
	err := aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history")
	}

	// let's make sure that we can't re-insert a new server
	// history into our log
	err = aud.Update("unknown", d.LatestSTR())
	if err != ErrAuditLog {
		t.Fatal("Expected an ErrAuditLog when updating an unknown server history")
	}
}

func TestGetLatestObservedSTR(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()
	err := aud.Insert("test-server", pk, nil, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history")
	}

	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "test-server",
		Epoch: uint64(d.LatestSTR().Epoch)})
	if err != ReqSuccess {
		t.Fatal("Unable to get latest observed STR")
	}

	obs := res.DirectoryResponse.(*STRList)
	if len(obs.STR) != 1 {
		t.Fatal("Expect returned STR to be not nil")
	}
	if obs.STR[0].Epoch != d.LatestSTR().Epoch {
		t.Fatal("Unexpected epoch for returned STR")
	}
}

func TestGetObservedSTRInEpoch(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	// create 10 epochs
	priorSTRs := make(map[uint64]*DirSTR)
	for i := 0; i < 10; i++ {
		priorSTRs[d.LatestSTR().Epoch] = d.LatestSTR()
		d.Update()
	}

	// now insert into the log
	err := aud.Insert("test-server", pk, priorSTRs, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history with prior STRs")
	}

	res, err := aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "test-server",
		Epoch: uint64(6)})

	if err != ReqSuccess {
		t.Fatal("Unable to get latest range of STRs")
	}

	obs := res.DirectoryResponse.(*STRList)
	if len(obs.STR) == 0 {
		t.Fatal("Expect returned STR to be not nil")
	}
	if len(obs.STR) != 5 {
		t.Fatal("Expect 5 returned STRs")
	}
	if obs.STR[0].Epoch != 6 || obs.STR[4].Epoch != d.LatestSTR().Epoch {
		t.Fatal("Unexpected epoch for returned STRs")
	}
}

func TestGetObservedSTRUnknown(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	// create 10 epochs
	priorSTRs := make(map[uint64]*DirSTR)
	for i := 0; i < 10; i++ {
		priorSTRs[d.LatestSTR().Epoch] = d.LatestSTR()
		d.Update()
	}

	// now insert into the log
	err := aud.Insert("test-server", pk, priorSTRs, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history with prior STRs")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "unknown",
		Epoch: uint64(d.LatestSTR().Epoch)})
	if err != ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for latest STR")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "unknown",
		Epoch:         uint64(6)})
	if err != ReqUnknownDirectory {
		t.Fatal("Expect ReqUnknownDirectory for older STR")
	}

}

func TestGetObservedSTRMalformed(t *testing.T) {
	// let's just create basic test directory and an empty audit log
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	// create 10 epochs
	priorSTRs := make(map[uint64]*DirSTR)
	for i := 0; i < 10; i++ {
		priorSTRs[d.LatestSTR().Epoch] = d.LatestSTR()
		d.Update()
	}

	// now insert into the log
	err := aud.Insert("test-server", pk, priorSTRs, d.LatestSTR())
	if err != nil {
		t.Fatal("Error inserting new server history with prior STRs")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "",
		Epoch: uint64(d.LatestSTR().Epoch)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect ErrMalFormedClientMessage for latest STR")
	}

	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "",
		Epoch:         uint64(6)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect ErrMalformedClientMessage for older STR")
	}

	// also test the epoch range
	_, err = aud.GetObservedSTRs(&AuditingRequest{
		DirectoryAddr: "",
		Epoch:         uint64(20)})
	if err != ErrMalformedClientMessage {
		t.Fatal("Expect ErrMalformedClientMessage for older STR")
	}

}
