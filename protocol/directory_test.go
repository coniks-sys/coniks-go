package protocol

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
)

func newDirectory(t *testing.T, useTBs bool) *ConiksDirectory {
	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	// epDeadline merkletree.TimeStamp, vrfKey vrf.PrivateKey,
	// signKey sign.PrivateKey, dirSize uint64, useTBs bool uint64
	d := InitDirectory(1, vrfKey, signKey, 10, useTBs)
	return d
}

func TestRegisterWithTB(t *testing.T) {
	// expect return a proof of absence
	// along with a TB of registering user
	d := newDirectory(t, true)

	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if res.Type != RegistrationType {
		t.Fatal("Expect response type", RegistrationType, "got", res.Type)
	}
	if err != Success {
		t.Fatal("Unable to register")
	}
	if ap := res.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if res.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}
	if d.tbs["alice"] == nil {
		t.Fatal("Expect TBs array has registering user")
	}
	d.Update()
	if len(d.tbs) != 0 {
		t.Fatal("Expect TBs array is empty")
	}
}

func TestRegisterExistedUserWithTB(t *testing.T) {
	d := newDirectory(t, true)
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != Success {
		t.Fatal("Unable to register")
	}
	// register in the same epoch
	// expect return a proof of absence
	// along with a TB of registering user
	// and error ErrorNameExisted
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := res.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if res.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}

	d.Update()
	// register in different epochs
	// expect return a proof of inclusion
	// and error ErrorNameExisted
	res, err = d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := res.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if res.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestRegisterWithoutTB(t *testing.T) {
	// expect return a proof of absence
	d := newDirectory(t, false)
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != Success {
		t.Fatal("Unable to register")
	}
	if ap := res.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if res.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestRegisterExistedUserWithoutTB(t *testing.T) {
	d := newDirectory(t, false)
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != Success {
		t.Fatal("Unable to register")
	}

	d.Update()
	// expect return a proof of inclusion
	// and error ErrorNameExisted
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := res.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if res.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}
