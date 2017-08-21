package protocol

import "testing"

func TestVerifyHashChain(t *testing.T) {
	var N uint64 = 100
	d, pk := NewTestDirectory(t, true)
	savedSTR := d.LatestSTR()
	for i := uint64(1); i < N; i++ {
		d.Update()
		str := d.LatestSTR()
		if i != str.Epoch {
			t.Fatal("Epochs aren't increasing.")
		}
		if !pk.Verify(str.Serialize(), str.Signature) {
			t.Fatal("Invalid STR signature at epoch", i)
		}
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Spurious STR at epoch", i)
		}
		savedSTR = str
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
	dirInitHash := ComputeDirectoryIdentity(hist[0])
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
	dirInitHash := ComputeDirectoryIdentity(hist[0])
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
	dirInitHash := ComputeDirectoryIdentity(hist[0])
	h, _ := aud.get(dirInitHash)

	// try to verify a new STR with a bad previous STR hash:
	// case str.Epoch != verifiedSTR.Epoch+1 in
	// str.VerifyHashChain()
	if str.VerifyHashChain(h.VerifiedSTR()) {
		t.Fatal("Expect hash chain verification to fail with bad previos epoch")
	}
}
