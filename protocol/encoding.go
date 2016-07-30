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
	return json.Marshal(&struct {
		Index     string `json:"index"`
		Value     string `json:"value"`
		Signature string `json:"signature"`
	}{
		Index:     b64en(tb.Index),
		Value:     b64en(tb.Value),
		Signature: b64en(tb.Signature),
	})
}

func MarshalSTR(str *merkletree.SignedTreeRoot) ([]byte, error) {
	return json.Marshal(str)
}

func MarshalAuthenticationPath(ap *merkletree.AuthenticationPath) ([]byte, error) {
	var prunedTree []string
	for i := range ap.PrunedTree {
		prunedTree = append(prunedTree, b64en(ap.PrunedTree[i]))
	}

	type Leaf struct {
		Level      int    `json:"level"`
		Index      string `json:"index"`
		Value      string `json:"value"`
		IsEmpty    bool   `json:"is_empty"`
		Commitment string `json:"commitment"`
	}

	return json.Marshal(&struct {
		TreeNonce   string   `json:"tree_nonce"`
		LookupIndex string   `json:"lookup_index"`
		VrfProof    string   `json:"vrf_proof"`
		PrunedTree  []string `json:"pruned_tree"`
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
