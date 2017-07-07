package protocol

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

// TODO: refactor the function signature after resolving #47

// NewTestDirectory creates a ConiksDirectory used for testing server-side
// CONIKS operations.
func NewTestDirectory(t *testing.T, useTBs bool) (
	*ConiksDirectory, sign.PublicKey) {

	// FIXME: NewTestDirectory should use a fixed VRF and Signing keys.
	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := signKey.Public()
	// epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey,
	// signKey sign.PrivateKey, dirSize uint64, useTBs bool
	d := NewDirectory(1, vrfKey, signKey, 10, useTBs)
	return d, pk
}

// NewTestAuditLog creates a ConiksAuditLog and corresponding
// ConiksDirectory used for testing auditor-side CONIKS operations.
// The new audit log can be initialized with the number of epochs
// indicating the length of the directory history with which to
// initialize the log; if numEpochs > 0, the history contains numEpochs+1
// STRs as it always includes the STR after the last directory update
func NewTestAuditLog(t *testing.T, numEpochs int) (*ConiksDirectory, ConiksAuditLog, []*DirSTR) {
	d, pk := NewTestDirectory(t, true)
	aud := NewAuditLog()

	var hist []*DirSTR
	for ep := 0; ep < numEpochs; ep++ {
		hist = append(hist, d.LatestSTR())
		d.Update()
	}
	// always include the actual latest STR
	hist = append(hist, d.LatestSTR())

	err := aud.Insert("test-server", pk, hist)
	if err != nil {
		t.Fatalf("Error inserting a new history with %d STRs", numEpochs+1)
	}

	return d, aud, hist
}
