package auditlog

import (
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

// NewTestAuditLog creates a ConiksAuditLog and corresponding
// ConiksDirectory used for testing auditor-side CONIKS operations.
// The new audit log can be initialized with the number of epochs
// indicating the length of the directory history with which to
// initialize the log; if numEpochs > 0, the history contains numEpochs+1
// STRs as it always includes the STR after the last directory update
func NewTestAuditLog(t *testing.T, numEpochs int) (
	*directory.ConiksDirectory, ConiksAuditLog, []*protocol.DirSTR) {
	d, pk := directory.NewTestDirectory(t, true)
	aud := New()

	var hist []*protocol.DirSTR
	for ep := 0; ep < numEpochs; ep++ {
		hist = append(hist, d.LatestSTR())
		d.Update()
	}
	// always include the actual latest STR
	hist = append(hist, d.LatestSTR())

	err := aud.InitHistory("test-server", pk, hist)
	if err != nil {
		t.Fatalf("Error inserting a new history with %d STRs", numEpochs+1)
	}

	return d, aud, hist
}
