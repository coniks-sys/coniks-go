package keyserver

import (
	"testing"

	. "github.com/coniks-sys/coniks-go/protocol"
)

func TestDirectoryKeyLookupInEpochBadEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, false)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid KeyLookupInEpochRequest (epoch > d.LatestEpoch())
	// Expect ErrorMalformedClientMessage
	req := &Request{
		Type:    KeyLookupInEpochType,
		Request: &KeyLookupInEpochRequest{"alice", uint64(6)},
	}

	_, err := handleOps(d, req)
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}
}

func TestMonitoringBadStartEpoch(t *testing.T) {
	N := 3

	d, _ := NewTestDirectory(t, false)
	for i := 0; i < N; i++ {
		d.Update()
	}

	// Send an invalid MonitoringRequest (startEpoch > d.LatestEpoch())
	// Expect ErrorMalformedClientMessage
	req := &Request{
		Type:    MonitoringType,
		Request: &MonitoringRequest{"alice", uint64(6), uint64(10)},
	}
	_, err := handleOps(d, req)
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}

	// Send an invalid MonitoringRequest (startEpoch > EndEpoch)
	// Expect ErrorMalformedClientMessage
	req = &Request{
		Type:    MonitoringType,
		Request: &MonitoringRequest{"alice", uint64(2), uint64(0)},
	}
	_, err = handleOps(d, req)
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}
}
