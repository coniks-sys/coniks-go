package client

import (
	"encoding/json"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
)

func TestUnmarshalErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ErrMalformedClientMessage)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res := UnmarshalResponse(protocol.RegistrationType, msg)
	if res.Error != protocol.ErrMalformedClientMessage {
		t.Error("Expect error", protocol.ErrMalformedClientMessage,
			"got", res.Error)
	}
}

func TestUnmarshalMalformedErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ReqNameNotFound)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res := UnmarshalResponse(protocol.RegistrationType, msg)
	if res.Error != protocol.ErrMalformedDirectoryMessage {
		t.Error("Expect error", protocol.ErrMalformedDirectoryMessage,
			"got", res.Error)
	}
}
