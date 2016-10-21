package protocol

import "testing"

var (
	uname = "alice"
	key   = []byte("key")
)

func TestVerifyWithError(t *testing.T) {
	d, pk := NewTestDirectory(t, false)

	// modify the pinning STR so that the consistency check should fail.
	str := append([]byte{}, d.LatestSTR().Signature...)
	str[0]++

	cs := NewCC(str, false, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err := cs.Verify(RegistrationType, res, uname, key); err != ErrorBadSTR {
		t.Fatal("Expect", ErrorBadSTR, "got", err)
	}
}

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cs := NewCC(d.LatestSTR().Signature, true, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if cs.Verify(RegistrationType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	if len(cs.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// test error name existed
	res, err := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	// expect a proof of inclusion even this binding wasn't "inserted" in this epoch
	if err := cs.Verify(RegistrationType, res, uname, key); err != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	if len(cs.TBs) != 2 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// re-register in a different epoch
	d.Update()
	res, err = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if cs.Verify(RegistrationType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}
	if len(cs.TBs) != 0 {
		t.Error("Expect the directory to insert the binding as promised")
	}
}

func TestVerifyRegistrationResponseWithoutTB(t *testing.T) {
	d, pk := NewTestDirectory(t, false)

	cs := NewCC(d.LatestSTR().Signature, false, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if cs.Verify(RegistrationType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// re-register in a different epoch
	d.Update()
	res, err := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if cs.Verify(RegistrationType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cs := NewCC(d.LatestSTR().Signature, true, pk)

	// do lookup first
	res, err := d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// register
	res, _ = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	// do lookup in the same epoch
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	// do lookup in the different epoch
	d.Update()
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	// test error name not found
	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cs.Verify(KeyLookupType, res, "bob", nil) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}
}

func TestVerifyKeyLookupResponseWithoutTB(t *testing.T) {
	d, pk := NewTestDirectory(t, false)

	cs := NewCC(d.LatestSTR().Signature, false, pk)

	// do lookup first
	res, err := d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// register
	res, _ = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	// do lookup in the same epoch
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// do lookup in the different epoch
	d.Update()
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cs.Verify(KeyLookupType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	// test error name not found
	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cs.Verify(KeyLookupType, res, "bob", nil) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}
}
