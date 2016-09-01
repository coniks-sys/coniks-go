package protocol

import (
	"bytes"
	"testing"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
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
	// signKey sign.PrivateKey, dirSize uint64, useTBs bool
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
	df := res.(*DirectoryProof)
	if df.Type != RegistrationType {
		t.Fatal("Expect response type", RegistrationType, "got", df.Type)
	}
	if err != Success {
		t.Fatal("Unable to register")
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}
	if d.tbs["alice"] == nil {
		t.Fatal("Expect TBs array has registering user")
	}
	d.Update(nil)
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
	df := res.(*DirectoryProof)
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil {
		t.Fatal("Expect returned TB is not nil")
	}

	d.Update(nil)
	// register in different epochs
	// expect return a proof of inclusion
	// and error ErrorNameExisted
	res, err = d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df = res.(*DirectoryProof)
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestRegisterWithoutTB(t *testing.T) {
	// expect return a proof of absence
	d := newDirectory(t, false)
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.(*DirectoryProof)
	if err != Success {
		t.Fatal("Unable to register")
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB != nil {
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

	d.Update(nil)
	// expect return a proof of inclusion
	// and error ErrorNameExisted
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	df := res.(*DirectoryProof)
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestKeyLookupWithTB(t *testing.T) {
	d := newDirectory(t, true)
	res, _ := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	tb := res.(*DirectoryProof).TB
	// lookup in the same epoch
	// expect a proof of absence and the TB of looking up user
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df := res.(*DirectoryProof)
	if df.Type != KeyLookupType {
		t.Fatal("Expect response type", KeyLookupType, "got", df.Type)
	}
	if df.Error != Success {
		t.Fatal("Expect no error", "got", df.Error)
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB == nil || !bytes.Equal(df.TB.Value, []byte("key")) {
		t.Fatal("Expect the TB of looking up user")
	}
	// assert that the server returns the same TB
	if !bytes.Equal(df.TB.Signature, tb.Signature) ||
		!bytes.Equal(df.TB.Index, tb.Index) ||
		!bytes.Equal(df.TB.Value, tb.Value) {
		t.Fatal("Expect the same TB for the registration and lookup")
	}

	d.Update(nil)
	// lookup in epoch after registering epoch
	// expect a proof of inclusion
	res, _ = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df = res.(*DirectoryProof)
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestKeyLookupWithoutTB(t *testing.T) {
	d := newDirectory(t, false)
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})

	// lookup in the same epoch
	// expect a proof of absence
	// and error ErrorNameNotFound
	res, err := d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df := res.(*DirectoryProof)
	if err != ErrorNameNotFound ||
		df.Error != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if ap := df.AP; ap == nil || bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of absence")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}

	d.Update(nil)
	// lookup in epoch after registering epoch
	// expect a proof of inclusion
	res, err = d.KeyLookup(&KeyLookupRequest{Username: "alice"})
	df = res.(*DirectoryProof)
	if ap := df.AP; ap == nil || !bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		t.Fatal("Expect a proof of inclusion")
	}
	if df.TB != nil {
		t.Fatal("Expect returned TB is nil")
	}
}

func TestDirectoryMonitoring(t *testing.T) {
	N := 10

	d := newDirectory(t, false)
	_, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})

	d.Update(nil)
	savedSTR := d.LatestSTR().Signature
	for i := 2; i < N; i++ {
		d.Update(nil)
	}

	// missed from epoch 2
	res, err := d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch})
	df := res.(*DirectoryProofs)
	if df.Type != MonitoringType {
		t.Fatal("Expect response type", MonitoringType, "got", df.Type)
	}
	if err != Success {
		t.Fatal("Unable to perform key lookup in epoch", 2)
	}
	expectNumberOfSTR := 10 - 2
	if len(df.AP) != expectNumberOfSTR || len(df.STR) != expectNumberOfSTR {
		t.Fatal("Expect", expectNumberOfSTR, "auth paths/STRs", "got", len(df.AP), "auth paths and", len(df.STR), "STRs")
	}

	for i := 0; i < expectNumberOfSTR; i++ {
		str := df.STR[i]
		if !merkletree.VerifyHashChain(str.PreviousSTRHash, savedSTR) {
			t.Fatal("Hash chain does not verify at epoch", i)
		}
		// we can ignore the auth path verification
		// since it is already tested in merkletree package
		savedSTR = str.Signature
	}

	// assert the number of STRs returned is correct
	res, err = d.Monitor(&MonitoringRequest{"alice", uint64(2), d.LatestSTR().Epoch + 5})
	df = res.(*DirectoryProofs)
	if df.Type != MonitoringType {
		t.Fatal("Expect response type", MonitoringType, "got", df.Type)
	}
	if err != Success {
		t.Fatal("Unable to perform key lookup in epoch", 2)
	}
	if len(df.AP) != expectNumberOfSTR || len(df.STR) != expectNumberOfSTR {
		t.Fatal("Expect", expectNumberOfSTR, "auth paths/STRs", "got", len(df.AP), "auth paths and", len(df.STR), "STRs")
	}
}

func TestDirectoryKeyLookupInEpoch(t *testing.T) {
	N := 3

	d := newDirectory(t, false)
	for i := 0; i < N; i++ {
		d.Update(nil)
	}

	// lookup at epoch 1, expect a proof of absence & ErrorNameNotFound
	res, err := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(1)})
	df := res.(*DirectoryProofs)
	if df.Type != KeyLookupInEpochType {
		t.Fatal("Expect response type", KeyLookupInEpochType, "got", df.Type)
	}
	if err != ErrorNameNotFound {
		t.Fatal("Expect error", ErrorNameNotFound, "got", err)
	}
	if len(df.AP) != 1 {
		t.Fatal("Expect only 1 auth path in response")
	}
	if len(df.STR) != int(d.LatestSTR().Epoch) {
		t.Fatal("Expect", d.LatestSTR().Epoch, "STRs", "got", len(df.STR))
	}

	d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte("key")})
	for i := 0; i < N; i++ {
		d.Update(nil)
	}

	res, err = d.KeyLookupInEpoch(&KeyLookupInEpochRequest{"alice", uint64(5)})
	df = res.(*DirectoryProofs)
	if df.Type != KeyLookupInEpochType {
		t.Fatal("Expect response type", KeyLookupInEpochType, "got", df.Type)
	}
	if err != Success {
		t.Fatal("Expect error", Success, "got", err)
	}
	if len(df.AP) != 1 {
		t.Fatal("Expect only 1 auth path in response")
	}
	if len(df.STR) != 2 {
		t.Fatal("Expect", 2, "STRs", "got", len(df.STR))
	}
}

func TestHandleOps(t *testing.T) {
	d := newDirectory(t, false)
	// Send an invalid KeyLookupInEpochRequest
	// Expect ErrorMalformedClientMessage
	req := &Request{
		Type:    MonitoringType,
		Request: &MonitoringRequest{"alice", uint64(2), uint64(0)},
	}
	_, err := d.HandleOps(req)
	if err != ErrorMalformedClientMessage {
		t.Fatal("Expect error", ErrorMalformedClientMessage, "got", err)
	}
}
