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

func (m *MerkleTree) GetSTR(ep int64) *SignedTreeRoot {
	// TODO: should we convert the return STR to another MerkleTree?
	// since we would use return value for lookup
	// also need to write test more accuracy
	// i.e.: in each epoch, add new user and then test lookup on the return str

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
