package utils

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
)

func TestBitsBytesConvert(t *testing.T) {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	var bits []bool
	for i := 0; i < 16; i++ {
		if r.Int()%2 == 0 {
			bits = append(bits, true)
		} else {
			bits = append(bits, false)
		}
	}

	bytes := ToBytes(bits)

	for i := uint32(0); i < 16; i++ {
		if GetNthBit(bytes, i) != bits[i] {
			t.Error("Wrong conversion")
		}
	}
}

func TestUInt32ToBytes(t *testing.T) {
	numInt := uint32(42)
	b := UInt32ToBytes(numInt)
	if binary.LittleEndian.Uint32(b) != numInt {
		t.Fatal("Conversion to bytes looks wrong!")
	}
}

func TestULongToBytes(t *testing.T) {
	numInt := uint64(42)
	b := ULongToBytes(numInt)
	if binary.LittleEndian.Uint64(b) != numInt {
		t.Fatal("Conversion to bytes looks wrong!")
	}
}

func TestLongToBytes(t *testing.T) {
	numInt := int64(42)
	b := LongToBytes(numInt)
	if int64(binary.LittleEndian.Uint64(b)) != numInt {
		t.Fatal("Conversion to bytes looks wrong!")
	}
	numInt = int64(-42)
	b = LongToBytes(numInt)
	if int64(binary.LittleEndian.Uint64(b)) != numInt {
		t.Fatal("Conversion to bytes looks wrong!")
	}
}
