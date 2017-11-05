package binutils

import (
        "bytes"
        "encoding/json"
        "testing"

        "github.com/coniks-sys/coniks-go/protocol"
        "github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestUnmarshalErrorResponse(t *testing.T) {
        errResponse := protocol.NewErrorResponse(protocol.ErrMalformedMessage)
        msg, err := json.Marshal(errResponse)
        if err != nil {
                t.Fatal(err)
        }
        res := UnmarshalResponse(protocol.RegistrationType, msg)
        if res.Error != protocol.ErrMalformedMessage {
                t.Error("Expect error", protocol.ErrMalformedMessage,
                        "got", res.Error)
        }
}

func TestUnmarshalErrorSTRHistoryResponse(t *testing.T) {
        errResponse := protocol.NewErrorResponse(protocol.ErrAuditLog)
        msg, err := json.Marshal(errResponse)
        if err != nil {
                t.Fatal(err)
        }
        res := UnmarshalResponse(protocol.AuditType, msg)
        if res.Error != protocol.ErrAuditLog {
                t.Error("Expect error", protocol.ErrAuditLog,
                        "got", res.Error)
        }
}

func TestUnmarshalMalformedDirectoryProof(t *testing.T) {
        errResponse := protocol.NewErrorResponse(protocol.ReqNameNotFound)
        msg, err := json.Marshal(errResponse)
        if err != nil {
                t.Fatal(err)
        }
        res := UnmarshalResponse(protocol.RegistrationType, msg)
        if res.Error != protocol.ErrMalformedMessage {
                t.Error("Expect error", protocol.ErrMalformedMessage,
                        "got", res.Error)
        }
}

func TestUnmarshalMalformedSTRHistoryRange(t *testing.T) {
        errResponse := protocol.NewErrorResponse(protocol.ReqNameNotFound)
        msg, err := json.Marshal(errResponse)
        if err != nil {
                t.Fatal(err)
        }
        res := UnmarshalResponse(protocol.STRType, msg)
        if res.Error != protocol.ErrMalformedMessage {
                t.Error("Expect error", protocol.ErrMalformedMessage,
                        "got", res.Error)
        }
}

func TestUnmarshalSampleClientMessage(t *testing.T) {
        d, _ := directory.NewTestDirectory(t, true)
        res := d.Register(&protocol.RegistrationRequest{
                Username: "alice",
                Key:      []byte("key")})
        msg, _ := MarshalResponse(res)
        response := UnmarshalResponse(protocol.RegistrationType, []byte(msg))
        str := response.DirectoryResponse.(*protocol.DirectoryProof).STR[0]
        if !bytes.Equal(d.LatestSTR().Serialize(), str.Serialize()) {
                t.Error("Cannot unmarshal Associate Data properly")
        }
}

func TestUnmarshalSampleAuditorMessage(t *testing.T) {
        d, _ := directory.NewTestDirectory(t, true)
        res := d.GetSTRHistory(&protocol.STRHistoryRequest{
                StartEpoch: uint64(0),
                EndEpoch:   uint64(1)})
        msg, _ := MarshalResponse(res)
        response := UnmarshalResponse(protocol.STRType, []byte(msg))
        str := response.DirectoryResponse.(*protocol.STRHistoryRange).STR[0]
        if !bytes.Equal(d.LatestSTR().Serialize(), str.Serialize()) {
                t.Error("Cannot unmarshal Associate Data properly")
        }
}
