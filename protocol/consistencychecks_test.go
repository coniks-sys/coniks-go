package protocol

import "testing"

var (
	uname = "alice"
	key   = []byte("key")
)

func TestVerifyWithError(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	// modify the pinning STR so that the consistency check should fail.
	str := *(d.LatestSTR())
	str.Signature = append([]byte{}, str.Signature...)
	str.Signature[0]++

	cc := NewCC(&str, true, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err := cc.UpdateConsistency(RegistrationType, res, uname, key); err != ErrorBadSTR {
		t.Fatal("Expect", ErrorBadSTR, "got", err)
	}
}

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if cc.UpdateConsistency(RegistrationType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// test error name existed
	res, err := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	// expect a proof of absence since this binding wasn't included in this epoch
	if err := cc.UpdateConsistency(RegistrationType, res, uname, key); err != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// test error name existed with different key
	res, err = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      []byte{1, 2, 3},
	})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	// expect a proof of absence since this binding wasn't included in this epoch
	if err := cc.UpdateConsistency(RegistrationType, res, uname, key); err != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// re-register in a different epoch
	// Since the fulfilled promise verification would be perform
	// when the client is monitoring, we do _not_ expect a TB's verification here.
	d.Update()
	res, err = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if cc.UpdateConsistency(RegistrationType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}
}

func TestVerifyFullfilledPromise(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      key})

	if cc.UpdateConsistency(RegistrationType, res, "alice", key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	res, _ = d.Register(&RegistrationRequest{
		Username: "bob",
		Key:      key})

	if cc.UpdateConsistency(RegistrationType, res, "bob", key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 2 {
		t.Fatal("Expect the directory to return signed promises")
	}

	d.Update()

	res, err := d.KeyLookup(&KeyLookupRequest{
		Username: "alice"})

	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := cc.UpdateConsistency(KeyLookupType, res, "alice", key); err != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result", "got", err)
	}

	// should contain the TBs of "bob"
	if len(cc.TBs) != 1 || cc.TBs["bob"] == nil {
		t.Error("Expect the directory to insert the binding as promised")
	}

	// register new binding and forget to verify the fulfilled promise
	res, err = d.Register(&RegistrationRequest{
		Username: "eve",
		Key:      key})

	if cc.UpdateConsistency(RegistrationType, res, "eve", key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}
	if len(cc.TBs) != 2 || cc.TBs["eve"] == nil {
		t.Fatal("Expect the directory to return signed promises")
	}

	d.Update()

	// bypass the hash chain verification
	cc.SavedSTR = d.LatestSTR()

	d.Update()

	res, err = d.KeyLookup(&KeyLookupRequest{
		Username: "eve"})

	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if err := cc.UpdateConsistency(KeyLookupType, res, "eve", key); err != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result", "got", err)
	}

	// TODO: expect eve's TB was instered as promise
	// should be resolve when we address monitoring
	// if len(cc.TBs) != 0 {
	// 	t.Error("Expect the directory to insert the binding as promised")
	// }
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	// do lookup first
	res, err := d.KeyLookup(&KeyLookupRequest{uname})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
	}
	if cc.UpdateConsistency(KeyLookupType, res, uname, key) != PassedWithAProofOfAbsence {
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
	if cc.UpdateConsistency(KeyLookupType, res, uname, key) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}

	// do lookup in the different epoch
	d.Update()
	res, err = d.KeyLookup(&KeyLookupRequest{uname})
	if err != Success {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cc.UpdateConsistency(KeyLookupType, res, uname, key) != PassedWithAProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	// test error name not found
	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
	if err != ErrorNameNotFound {
		t.Fatal("Expect error code", Success, "got", err)
	}
	if cc.UpdateConsistency(KeyLookupType, res, "bob", nil) != PassedWithAProofOfAbsence {
		t.Fatal("Unexpected verification result")
	}
}
