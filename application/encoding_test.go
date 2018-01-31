package application

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestUnmarshalErrorResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  protocol.ErrorCode
		want protocol.ErrorCode
	}{
		{protocol.ErrDirectory.Error(), protocol.ErrDirectory, protocol.ErrDirectory},
		{protocol.ErrAuditLog.Error(), protocol.ErrAuditLog, protocol.ErrAuditLog},
		{protocol.ErrMalformedMessage.Error(), protocol.ErrMalformedMessage, protocol.ErrMalformedMessage},
		{"Malformed Error Response", protocol.ReqNameNotFound, protocol.ErrMalformedMessage},
	} {
		errResponse := protocol.NewErrorResponse(tc.err)
		msg, err := json.Marshal(errResponse)
		if err != nil {
			t.Fatal(err)
		}
		res := UnmarshalResponse(protocol.RegistrationType, msg)
		if got, want := res.Error, tc.want; got != want {
			t.Error("Expect error", want,
				"got", got)
		}
	}
}

func TestUnmarshalSampleMessage(t *testing.T) {
	d := directory.NewTestDirectory(t)
	res := d.GetSTRHistory(&protocol.STRHistoryRequest{
		StartEpoch: 0,
		EndEpoch:   0})
	msg, _ := MarshalResponse(res)
	response := UnmarshalResponse(protocol.STRType, []byte(msg))
	str := response.DirectoryResponse.(*protocol.STRHistoryRange).STR[0]
	if !bytes.Equal(d.LatestSTR().Serialize(), str.Serialize()) {
		t.Error("Cannot unmarshal Associate Data properly")
	}
}
