package auditor

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestComputeDirectoryIdentity(t *testing.T) {
	d := directory.NewTestDirectory(t)
	str0 := d.LatestSTR()
	d.Update()
	str1 := d.LatestSTR()

	tests := []struct {
		name string
		str  *protocol.DirSTR
		want []byte
	}{
		{"normal", str0, dh("fd0584f79054f8113f21e5450e0ad21c9221fc159334c7bc1644e3e2a0fb5060")},
		{"panic", str1, []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "panic" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic")
					}
				}()
			}
			if got, want := ComputeDirectoryIdentity(tt.str), tt.want; !bytes.Equal(got[:], want) {
				t.Errorf("ComputeDirectoryIdentity() = %#v, want %#v", got, want)
			}
		})
	}
}

// decode hex string to byte array
func dh(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return result
}
