package merkletree

import (
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
)

var (
	ErrHistoryExisted = errors.New("[merkletree] trying to override existing history")
	ErrBadEpoch       = errors.New("[merkletree] next epoch's STR has bad epoch ")
)

type History struct {
	tree          *MerkleTree
	currentSTR    *SignedTreeRoot
	epochInterval int64
}

func NewHistory(m *MerkleTree, key crypto.KeyPair, startEp, epInterval int64) *History {
	h := new(History)
	h.tree = m
	h.epochInterval = epInterval
	h.currentSTR = NewSTR(m, startEp, 0, make([]byte, crypto.HashSizeByte), key)
	return h
}

func (h *History) UpdateHistory(m *MerkleTree, nextEp int64) error {
	if nextEp < h.NextEpoch() {
		return ErrBadEpoch
	}
	nextStr := h.currentSTR.generateNextSTR(m, nextEp)
	h.currentSTR = nextStr
	return nil
}

func (h *History) Get(key string) (MerkleNode, []ProofNode) {
	str := h.currentSTR
	return lookUp(key, str)
}

func (h *History) GetInEpoch(key string, ep int64) (MerkleNode, []ProofNode) {
	str := h.GetSTR(ep)
	return lookUp(key, str)
}

func (h *History) GetSTR(ep int64) *SignedTreeRoot {
	pointer := h.currentSTR
	for pointer.epoch > ep && pointer != nil {
		if pointer.prev == nil {
			return nil
		}
		pointer = pointer.prev
	}
	return pointer
}

func (h *History) NextEpoch() int64 {
	if h.currentSTR == nil {
		return h.epochInterval
	}
	return h.epochInterval + h.currentSTR.epoch
}
