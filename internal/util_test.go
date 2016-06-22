package util

import (
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

	for i := 0; i < 16; i++ {
		if GetNthBit(bytes, i) != bits[i] {
			t.Error("Wrong conversion")
		}
	}
}
