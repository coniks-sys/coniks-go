package protocol

import "testing"

func TestVerifyHashChain(t *testing.T) {
	var N uint64 = 100
	d, pk := NewTestDirectory(t, true)
	savedSTR := d.LatestSTR()
	for i := uint64(1); i < N; i++ {
		d.Update()
		str := d.LatestSTR()
		if i != str.Epoch {
			t.Fatal("Epochs aren't increasing.")
		}
		if !pk.Verify(str.Serialize(), str.Signature) {
			t.Fatal("Invalid STR signature at epoch", i)
		}
		if !str.VerifyHashChain(savedSTR) {
			t.Fatal("Spurious STR at epoch", i)
		}
		savedSTR = str
	}
}
