package merkletree

import (
	"errors"

	"github.com/coniks-sys/libmerkleprefixtree-go/crypto"
)

var (
	ErrHistoryExisted = errors.New("[merkletree] trying to override existing history")
	ErrBadEpoch       = errors.New("[merkletree] next epoch's STR has bad epoch ")
)

var currentSTR *SignedTreeRoot
var epochInterval int64

func (m *MerkleTree) InitHistory(startEp, epInterval int64) error {
	if currentSTR != nil {
		return ErrHistoryExisted
	}
	epochInterval = epInterval
	currentSTR = m.generateSTR(startEp, 0, make([]byte, crypto.HashSizeByte))
	return nil
}

func (m *MerkleTree) UpdateHistory(nextEp int64) error {
	if nextEp < NextEpoch() {
		return ErrBadEpoch
	}
	nextStr := m.generateNextSTR(nextEp)

	currentSTR = nextStr
	return nil
}

func GetSTR(ep int64) *SignedTreeRoot {
	pointer := getCurrentSTR()
	for pointer.epoch > ep && pointer != nil {
		if pointer.prev == nil {
			return nil
		}
		pointer = pointer.prev
	}
	return pointer
}

func getCurrentSTR() *SignedTreeRoot {
	return currentSTR
}

func NextEpoch() int64 {
	if currentSTR == nil {
		return epochInterval
	}
	return epochInterval + currentSTR.epoch
}
