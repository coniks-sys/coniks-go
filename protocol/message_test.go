package protocol

import "testing"

var (
	uname = "alice"
	key   = []byte("key")
)

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	currentEpoch := uint64(0)
	savedSTR := d.LatestSTR().Signature

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}

	// test error name existed
	savedSTR = d.LatestSTR().Signature
	res, err := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}

	// re-register in a different epoch
	savedSTR = d.LatestSTR().Signature
	d.Update()
	res, err = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
}

func TestVerifyRegistrationResponseWithoutTB(t *testing.T) {
	d, pk := NewTestDirectory(t, false)
	currentEpoch := uint64(0)
	savedSTR := d.LatestSTR().Signature

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}

	// re-register in a different epoch
	savedSTR = d.LatestSTR().Signature
	d.Update()
	res, err := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)
	currentEpoch := uint64(0)
	savedSTR := d.LatestSTR().Signature

	// do lookup first
	res, err := d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
	savedSTR = res.DirectoryResponse.(*DirectoryProof).STR.Signature
	// register
	res, _ = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	// do lookup in the same epoch
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}

	// do lookup in the different epoch
	d.Update()
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
	// test error name not found
	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := res.Verify("bob", key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
}

func TestVerifyKeyLookupResponseWithoutTB(t *testing.T) {
	d, pk := NewTestDirectory(t, false)
	currentEpoch := uint64(0)
	savedSTR := d.LatestSTR().Signature

	// do lookup first
	res, err := d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
	savedSTR = res.DirectoryResponse.(*DirectoryProof).STR.Signature
	// register
	res, _ = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	// do lookup in the same epoch
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}

	// do lookup in the different epoch
	d.Update()
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := res.Verify(uname, key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
	// test error name not found
	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := res.Verify("bob", key, currentEpoch, savedSTR, pk); err != Passed {
		t.Fatal(err.Error())
	}
}
