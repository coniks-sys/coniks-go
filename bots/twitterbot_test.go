package bots

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
)

func TestCannotUnmarshallRequest(t *testing.T) {
	username := "alice"
	request := `{
        "unknown_field": "unknown_value"
    }`
	bot := new(TwitterBot)
	response := bot.HandleRegistration(username, []byte(request))
	if response != fmt.Sprintf(`{"Error":%d}`, protocol.ErrMalformedClientMessage) {
		t.Error("Unexpected response", "got", response)
	}
}

func TestInvalidRequestType(t *testing.T) {
	username := "alice"
	request, _ := json.Marshal(&protocol.Request{
		Type: protocol.KeyLookupType,
		Request: &protocol.RegistrationRequest{
			Username: username + "@twitter",
			Key:      []byte{1, 2, 3},
		},
	})

	bot := new(TwitterBot)
	response := bot.HandleRegistration(username, []byte(request))
	if response != fmt.Sprintf(`{"Error":%d}`, protocol.ErrMalformedClientMessage) {
		t.Error("Unexpected response", "got", response)
	}
}

func TestInvalidUsername(t *testing.T) {
	username := "bob"
	request, _ := json.Marshal(&protocol.Request{
		Type: protocol.RegistrationType,
		Request: &protocol.RegistrationRequest{
			Username: "alice@twitter",
			Key:      []byte{1, 2, 3},
		},
	})
	bot := new(TwitterBot)
	response := bot.HandleRegistration(username, []byte(request))
	if response != fmt.Sprintf(`{"Error":%d}`, protocol.ErrMalformedClientMessage) {
		t.Error("Unexpected response", "got", response)
	}
}
