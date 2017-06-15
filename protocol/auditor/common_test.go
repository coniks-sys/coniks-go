package auditor

import (
	"testing"

	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
)

func TestComputeDirectoryIdentity(t *testing.T) {
	d, _ := directory.NewTestDirectory(t, true)
	// str0 := d.LatestSTR()
	d.Update()
	str1 := d.LatestSTR()
	var unknown [crypto.HashSizeByte]byte
	type args struct {
		str *protocol.DirSTR
	}
	tests := []struct {
		name string
		args args
		want [crypto.HashSizeByte]byte
	}{
		// {"normal", args{str0}, ""},
		{"panic", args{str1}, unknown},
	}
	for _, tt := range tests {
		// FIXME: Refactor testing. See #18.
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "panic" {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("The code did not panic")
					}
				}()
			}
			if got := ComputeDirectoryIdentity(tt.args.str); got != tt.want {
				t.Errorf("ComputeDirectoryIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}
