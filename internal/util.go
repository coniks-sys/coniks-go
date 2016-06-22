package util

// Finds the bit in the byte array bs
// at offset offset, and determines whether it is 1 or 0.
// return true if the nth bit is 1, false otherwise.
// from MSB to LSB order
func GetNthBit(bs []byte, offset int) bool {
	arrayOffset := offset / 8
	bitOfByte := offset % 8

	masked := int(bs[arrayOffset] & (1 << uint(7-bitOfByte)))
	return masked != 0
}
