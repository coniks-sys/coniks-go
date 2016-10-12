package protocol

import "testing"

var (
	uname = "alice"
	key   = []byte("key")
)

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cs := NewConiksClient(d.LatestSTR().Signature, true, pk)

	res, _ := d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
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
	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}

	// re-register in a different epoch
	d.Update()
	res, err = d.Register(&RegistrationRequest{
		Username: uname,
		Key:      key})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfInclusion {
		t.Fatal("Unexpected verification result")
	}
	if len(cs.TBs) != 0 {
		t.Error("Expect the directory to insert the binding as promised")
	}
}

// func TestVerifyRegistrationResponseWithoutTB(t *testing.T) {
// 	d, pk := NewTestDirectory(t, false)

// 	cs := NewConiksClient(d.LatestSTR().Signature, false, pk)

// 	res, _ := d.Register(&RegistrationRequest{
// 		Username: uname,
// 		Key:      key})
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// re-register in a different epoch
// 	d.Update()
// 	res, err := d.Register(&RegistrationRequest{
// 		Username: uname,
// 		Key:      key})
// 	if err != ErrorNameExisted {
// 		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfInclusion {
// 		t.Fatal("Unexpected verification result")
// 	}
// }

// func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
// 	d, pk := NewTestDirectory(t, true)

// 	cs := NewConiksClient(d.LatestSTR().Signature, true, pk)

// 	// do lookup first
// 	res, err := d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != ErrorNameNotFound {
// 		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// register
// 	res, _ = d.Register(&RegistrationRequest{
// 		Username: uname,
// 		Key:      key})
// 	// do lookup in the same epoch
// 	res, err = d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != Success {
// 		t.Fatal("Expect error code", Success, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// do lookup in the different epoch
// 	d.Update()
// 	res, err = d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != Success {
// 		t.Fatal("Expect error code", Success, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfInclusion {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// test error name not found
// 	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
// 	if err != ErrorNameNotFound {
// 		t.Fatal("Expect error code", Success, "got", err)
// 	}
// 	if cs.Verify(res, "bob", nil); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}
// }

// func TestVerifyKeyLookupResponseWithoutTB(t *testing.T) {
// 	d, pk := NewTestDirectory(t, false)

// 	cs := NewConiksClient(d.LatestSTR().Signature, false, pk)

// 	// do lookup first
// 	res, err := d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != ErrorNameNotFound {
// 		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// register
// 	res, _ = d.Register(&RegistrationRequest{
// 		Username: uname,
// 		Key:      key})
// 	// do lookup in the same epoch
// 	res, err = d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != ErrorNameNotFound {
// 		t.Fatal("Expect error code", ErrorNameNotFound, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// do lookup in the different epoch
// 	d.Update()
// 	res, err = d.KeyLookup(&KeyLookupRequest{uname})
// 	if err != Success {
// 		t.Fatal("Expect error code", Success, "got", err)
// 	}
// 	if cs.Verify(res, uname, key); cs.VerificationResult != Passed && cs.ProofType != ProofOfInclusion {
// 		t.Fatal("Unexpected verification result")
// 	}

// 	// test error name not found
// 	res, err = d.KeyLookup(&KeyLookupRequest{"bob"})
// 	if err != ErrorNameNotFound {
// 		t.Fatal("Expect error code", Success, "got", err)
// 	}
// 	if cs.Verify(res, "bob", nil); cs.VerificationResult != Passed && cs.ProofType != ProofOfAbsence {
// 		t.Fatal("Unexpected verification result")
// 	}
// }
