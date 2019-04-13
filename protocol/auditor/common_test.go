package auditor

import (
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

	for _, tc := range []struct {
		name string
		str  *protocol.DirSTR
		want string
	}{
		{"normal", str0, "b2c6300df0d0d0fb26c3be959a33cc978fc1969090fd19d95dd76cd43b809949"},
		{"panic", str1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "panic" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic")
					}
				}()
			}
			if got, want := ComputeDirectoryIdentity(tc.str), tc.want; want != hex.EncodeToString(got[:]) {
				t.Errorf("ComputeDirectoryIdentity() = %#v, want %#v", got, want)
			}
		})
	}
}
