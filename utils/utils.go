package utils

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// GetNthBit finds the bit in the byte array bs
// at offset offset, and determines whether it is 1 or 0.
// return true if the nth bit is 1, false otherwise.
// from MSB to LSB order
func GetNthBit(bs []byte, offset uint32) bool {
	arrayOffset := offset / 8
	bitOfByte := offset % 8

	masked := int(bs[arrayOffset] & (1 << uint(7-bitOfByte)))
	return masked != 0
}

// LongToBytes converts an int64 variable to byte array
// in little endian format
func LongToBytes(num int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(num))
	return buf
}

// ULongToBytes converts an uint64 variable to byte array
// in little endian format
func ULongToBytes(num uint64) []byte {
	return LongToBytes(int64(num))
}

// UInt32ToBytes converts an uint32 variable to byte array
// in little endian format
func UInt32ToBytes(num uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, num)
	return buf
}

// WriteFile writes buf to a file whose path is indicated by filename.
// The file permissions are set to 0644.
func WriteFile(filename string, buf bytes.Buffer) {
	if _, err := os.Stat(filename); err == nil {
		log.Printf("%s already exists\n", filename)
		return
	}

	if err := ioutil.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		log.Printf(err.Error())
		return
	}
}

// ResolvePath returns the absolute path of file.
// This will use other as a base path if file is just a file name.
func ResolvePath(file, other string) string {
	if !filepath.IsAbs(file) {
		file = filepath.Join(filepath.Dir(other), file)
	}
	return file
}
