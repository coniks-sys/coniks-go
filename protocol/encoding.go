// Defines methods/functions to encode/decode messages between client and server.
// Currently this module supports JSON marshal/unmarshal only.
// Protobuf would be supported in the feature.

package protocol

import (
	"encoding/base64"
	"encoding/json"

	"github.com/coniks-sys/coniks-go/merkletree"
)

var b64en = base64.StdEncoding.EncodeToString

func MarshalTemporaryBinding(tb *merkletree.TemporaryBinding) ([]byte, error) {
	return json.Marshal(tb)
}

func MarshalSTR(str *merkletree.SignedTreeRoot) ([]byte, error) {
	policies, err := json.Marshal(str.Policies)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&struct {
		TreeHash        []byte
		Epoch           uint64
		PreviousEpoch   uint64
		PreviousSTRHash []byte
		Policies        json.RawMessage
		Signature       []byte
	}{
		TreeHash:        str.Root(),
		Epoch:           str.Epoch,
		PreviousEpoch:   str.PreviousEpoch,
		PreviousSTRHash: str.PreviousSTRHash,
		Policies:        policies,
		Signature:       str.Signature,
	})
}

func MarshalAuthenticationPath(ap *merkletree.AuthenticationPath) ([]byte, error) {
	var prunedTree []string
	for i := range ap.PrunedTree {
		prunedTree = append(prunedTree, b64en(ap.PrunedTree[i][:]))
	}

	type Leaf struct {
		Level      int
		Index      string
		Value      string
		IsEmpty    bool
		Commitment string
	}

	return json.Marshal(&struct {
		TreeNonce   string
		LookupIndex string
		VrfProof    string
		PrunedTree  []string
		Leaf        Leaf
	}{
		TreeNonce:   b64en(ap.TreeNonce),
		LookupIndex: b64en(ap.LookupIndex),
		VrfProof:    b64en(ap.VrfProof),
		PrunedTree:  prunedTree,
		Leaf: Leaf{
			Level:      ap.Leaf.Level(),
			Index:      b64en(ap.Leaf.Index()),
			Value:      b64en(ap.Leaf.Value()),
			Commitment: b64en(ap.Leaf.Commitment()),
			IsEmpty:    ap.Leaf.IsEmpty(),
		},
	})
}
