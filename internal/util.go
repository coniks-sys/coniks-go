package util

import "encoding/binary"

// Finds the byte in the byte array bs
// at offset offset, and determines whether it is 1 or 0.
// return true if the nth bit is 1, false otherwise.
// from MSB to LSB order
func GetNthBit(bs []byte, offset int) bool {
	arrayOffset := offset / 8
	bitOfByte := offset % 8

	masked := int(bs[arrayOffset] & (1 << uint(7-bitOfByte)))
	return masked != 0
}

func LongToBytes(num int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(num))
	return buf
}

func IntToBytes(num int) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(num))
	return buf
}
