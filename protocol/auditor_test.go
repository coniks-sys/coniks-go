package protocol

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
)

func TestComputeDirectoryIdentity(t *testing.T) {
	d, _ := NewTestDirectory(t, true)
	// str0 := d.LatestSTR()
	d.Update()
	str1 := d.LatestSTR()
	var unknown [crypto.HashSizeByte]byte
	type args struct {
		str *DirSTR
	}
	tests := []struct {
		name string
		args args
		want [crypto.HashSizeByte]byte
	}{
		// {"normal", args{str0}, ""},
		{"panic", args{str1}, unknown},
	}
	for _, tt := range tests {
		// FIXME: Refactor testing. See #18.
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "panic" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic")
					}
				}()
			}
			if got := ComputeDirectoryIdentity(tt.args.str); got != tt.want {
				t.Errorf("ComputeDirectoryIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditBadSTRSignature(t *testing.T) {
	// create basic test directory and audit log with 4 STRs
	d, aud, hist := NewTestAuditLog(t, 3)

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])

	// update the directory a few more times and then try
	// to update
	d.Update()

	h, _ := aud.get(dirInitHash)

	// modify the latest STR so that the consistency check fails
	str := d.LatestSTR()
	str2 := *str.SignedTreeRoot
	str2.Signature = append([]byte{}, str.Signature...)
	str2.Signature[0]++
	str.SignedTreeRoot = &str2

	// try to audit a new STR with a bad signature:
	// case signature verification failure in verifySTRConsistency()
	resp, _ := NewSTRHistoryRange([]*DirSTR{str})
	err := h.Audit(resp)
	if err != CheckBadSignature {
		t.Error("Expect", CheckBadSignature, "got", err)
	}
}

// used to be TestVerifyWithError in consistencychecks_test.go
func TestAuditBadSameEpoch(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	str := d.LatestSTR()

	// modify the pinning STR so that the consistency check should fail.
	str2 := *str.SignedTreeRoot
	str2.Signature = append([]byte{}, str.Signature...)
	str2.Signature[0]++
	str.SignedTreeRoot = &str2

	cc := NewCC(str, true, pk)

	// try to audit a diverging STR for the same epoch
	// case compareWithVerified() == false in checkAgainstVerified()
	err := cc.AuditDirectory([]*DirSTR{d.LatestSTR()})
	if err != CheckBadSTR {
		t.Error("Expect", CheckBadSTR, "got", err)
	}
}

func TestAuditBadNewSTREpoch(t *testing.T) {
	// create basic test directory and audit log with 4 STRs
	d, aud, hist := NewTestAuditLog(t, 3)

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// update the directory a few more times and then try
	// to update
	d.Update()
	d.Update()

	// try to audit only STR epoch 4:
	// case str.Epoch > verifiedSTR.Epoch+1 in checkAgainstVerifiedSTR()
	resp, _ := NewSTRHistoryRange([]*DirSTR{d.LatestSTR()})
	err := h.Audit(resp)
	if err != CheckBadSTR {
		t.Error("str.Epoch > verified.Epoch+1 - Expect", CheckBadSTR, "got", err)
	}

	// try to re-audit only STR epoch 2:
	// case str.Epoch < verifiedSTR.Epoch in checkAgainstVerifiedSTR()
	resp, _ = d.GetSTRHistory(&STRHistoryRequest{
		StartEpoch: uint64(2),
		EndEpoch:   uint64(2)})

	err = h.Audit(resp)
	if err != CheckBadSTR {
		t.Error("str.Epoch < verified.Epoch - Expect", CheckBadSTR, "got", err)
	}
}

func TestAuditMalformedSTRRange(t *testing.T) {
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

	// make a malformed range
	strs.STR[2] = nil

	// compute the hash of the initial STR for later lookups
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// try to audit a malformed STR range
	// case str[i] == nil in verifySTRRange() loop
	err1 := h.AuditDirectory(strs.STR)
	if err1 != ErrMalformedDirectoryMessage {
		t.Error("Expect", ErrMalformedDirectoryMessage, "got", err1)
	}
}
