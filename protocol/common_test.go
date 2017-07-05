package protocol

import (
	"testing"
)

func TestComputeDirectoryIdentity(t *testing.T) {
	// FIXME: NewTestDirectory should use a fixed VRF and Signing keys.
	d, _ := NewTestDirectory(t, true)
	// str0 := d.LatestSTR()
	d.Update()
	str1 := d.LatestSTR()
	type args struct {
		str *DirSTR
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// {"normal", args{str0}, ""},
		{"panic", args{str1}, ""},
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
