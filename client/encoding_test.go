package client

import (
	"encoding/json"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
)

func TestUnmarshalErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ErrorMalformedClientMessage)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res, e := UnmarshalResponse(protocol.RegistrationType, msg)
	if res != nil || e != protocol.ErrorMalformedClientMessage {
		t.Error("Expect error", protocol.ErrorMalformedClientMessage,
			"got", e)
	}
}

func TestUnmarshalMalformedErrorResponse(t *testing.T) {
	errResponse := protocol.NewErrorResponse(protocol.ErrorNameNotFound)
	msg, err := json.Marshal(errResponse)
	if err != nil {
		t.Fatal(err)
	}
	res, e := UnmarshalResponse(protocol.RegistrationType, msg)
	if res != nil || e != protocol.ErrorMalformedDirectoryMessage {
		t.Error("Expect error", protocol.ErrorMalformedDirectoryMessage,
			"got", e)
	}
}
