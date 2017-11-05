package coniksauditor

import (
        "encoding/json"

        "github.com/coniks-sys/coniks-go/protocol"
)

// CreateSTRRequestMsg returns a JSON encoding of
// a protocol.STRHistoryRequest for the given (start, end) epoch
// range.
func CreateSTRRequestMsg(start, end uint64) ([]byte, error) {
        return json.Marshal(&protocol.Request{
                Type: protocol.STRType,
                Request: &protocol.STRHistoryRequest{
                        StartEpoch: start,
                        EndEpoch:   end,
                },
        })
}
