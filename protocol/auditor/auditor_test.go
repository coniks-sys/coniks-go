package auditor

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestAuditBadSTRSignature(t *testing.T) {
	d := directory.NewTestDirectory(t)
	pk, _ := crypto.StaticSigning(t).Public()

	// create a generic auditor state
	aud := New(pk, d.LatestSTR())

	// update the directory a few more times and then try
	// to update
	d.Update()

	// modify the latest STR so that the consistency check fails
	str := d.LatestSTR()
	str2 := *str.SignedTreeRoot
	str2.Signature = append([]byte{}, str.Signature...)
	str2.Signature[0]++
	str.SignedTreeRoot = &str2

	// try to audit a new STR with a bad signature:
	// case signature verification failure in verifySTRConsistency()
	err := aud.AuditDirectory([]*protocol.DirSTR{str})
	if err != protocol.CheckBadSignature {
		t.Error("Expect", protocol.CheckBadSignature, "got", err)
	}
}

// used to be TestVerifyWithError in consistencychecks_test.go
func TestAuditBadSameEpoch(t *testing.T) {
	d := directory.NewTestDirectory(t)
	pk, _ := crypto.StaticSigning(t).Public()

	// create a generic auditor state
	aud := New(pk, d.LatestSTR())

	str := d.LatestSTR()
	// modify the pinned STR so that the consistency check should fail.
	str2 := *str.SignedTreeRoot
	str2.Signature = append([]byte{}, str.Signature...)
	str2.Signature[0]++
	str.SignedTreeRoot = &str2

	// try to audit a diverging STR for the same epoch
	// case compareWithVerified() == false in checkAgainstVerified()
	err := aud.AuditDirectory([]*protocol.DirSTR{str})
	if err != protocol.CheckBadSTR {
		t.Error("Expect", protocol.CheckBadSTR, "got", err)
	}
}

func TestAuditBadNewSTREpoch(t *testing.T) {
	d := directory.NewTestDirectory(t)
	pk, _ := crypto.StaticSigning(t).Public()

	// create a generic auditor state
	aud := New(pk, d.LatestSTR())

	// update the auditor to epoch 3
	for e := 0; e < 3; e++ {
		d.Update()
		aud.Update(d.LatestSTR())
	}

	// update the directory a few more times and then try
	// to update
	d.Update()
	d.Update()

	// try to audit only STR epoch 4:
	// case str.Epoch > verifiedSTR.Epoch+1 in checkAgainstVerifiedSTR()
	err := aud.AuditDirectory([]*protocol.DirSTR{d.LatestSTR()})
	if err != protocol.CheckBadSTR {
		t.Error("str.Epoch > verified.Epoch+1 - Expect", protocol.CheckBadSTR, "got", err)
	}

	// try to re-audit only STR epoch 2:
	// case str.Epoch < verifiedSTR.Epoch in checkAgainstVerifiedSTR()
	resp := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: uint64(2),
		EndEpoch:   uint64(2)})

	strs := resp.DirectoryResponse.(*protocol.STRHistoryRange)
	err = aud.AuditDirectory(strs.STR)
	if err != protocol.CheckBadSTR {
		t.Error("str.Epoch < verified.Epoch - Expect", protocol.CheckBadSTR, "got", err)
	}
}

func TestAuditMalformedSTRRange(t *testing.T) {
	d := directory.NewTestDirectory(t)
	pk, _ := crypto.StaticSigning(t).Public()

	// create a generic auditor state
	aud := New(pk, d.LatestSTR())

	// update the auditor to epoch 3
	for e := 0; e < 3; e++ {
		d.Update()
		aud.Update(d.LatestSTR())
	}

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
	// make a malformed range
	strs.STR[2] = nil

	// try to audit a malformed STR range
	// case str[i] == nil in verifySTRRange() loop
	err1 := aud.AuditDirectory(strs.STR)
	if err1 != protocol.ErrMalformedMessage {
		t.Error("Expect", protocol.ErrMalformedMessage, "got", err1)
	}
}
