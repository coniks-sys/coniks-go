package tests

import (
	"testing"

	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/client"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func newTestEnv(t *testing.T) (*directory.ConiksDirectory,
	*client.ConsistencyChecks) {
	d := directory.NewTestDirectory(t)
	pk, _ := staticSigningKey.Public()

	// create a shadow copy of d.LatestSTR()
	// so the latest STR of each side can be update independently.
	str := merkletree.NewSTR(staticSigningKey, d.LatestSTR().Policies,
		merkletree.StaticTree(t), 0, d.LatestSTR().PreviousSTRHash)
	dirSTR := protocol.NewDirSTR(str)
	cc := client.New(dirSTR, true, pk)

	return d, cc
}

func strRequest(start, end uint64) *protocol.STRHistoryRequest {
	return &protocol.STRHistoryRequest{
		StartEpoch: start,
		EndEpoch:   end,
	}
}

func TestGetSTRHistory(t *testing.T) {
	tests := []struct {
		name    string
		request *protocol.STRHistoryRequest
		want    error
	}{
		{"get next STR", strRequest(1, 1), nil},
		{"get verified STR", strRequest(0, 0), nil},
		{"get range from verified STR to the latest", strRequest(0, 10), nil},
		{"get next published STRs", strRequest(1, 10), nil},
		{"get inconsistency range", strRequest(2, 10), protocol.CheckBadSTR},
	}
	for _, tt := range tests {
		N := 8
		d, cc := newTestEnv(t)
		for i := 0; i < N; i++ {
			d.Update()
		}

		response := d.GetSTRHistory(tt.request)
		err := cc.UpdateSTR(response)
		if got, want := err, tt.want; got != want {
			t.Errorf("Test %s failed: got %#v, want %#v", tt.name, got.Error(), want)
		}
	}

}
