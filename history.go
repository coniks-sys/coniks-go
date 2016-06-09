package merkletree

import "errors"

var (
	ErrHistoryExisted = errors.New("[merkletree] trying to override existing history")
	ErrBadEpoch       = errors.New("[merkletree] next epoch's STR has bad epoch ")
)

var currentSTR *SignedTreeRoot
var epochInterval int64

func (m *MerkleTree) InitHistory(db DB, startEp, epInterval int64) error {
	if currentSTR != nil {
		return ErrHistoryExisted
	}
	epochInterval = epInterval
	currentSTR = m.generateSTR(startEp, 0, make([]byte, m.hash.HashSizeByte))
	err := saveSTR(db, currentSTR)
	return err
}

func (m *MerkleTree) UpdateHistory(db DB, nextEp int64) error {
	if nextEp < nextEpoch() {
		return ErrBadEpoch
	}
	nextStr := m.generateNextSTR(nextEp)

	currentSTR = nextStr
	err := saveSTR(db, currentSTR)
	return err
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

func nextEpoch() int64 {
	if currentSTR == nil {
		return epochInterval
	}
	return epochInterval + currentSTR.epoch
}
