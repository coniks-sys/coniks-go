package protocol

import "testing"

var (
	key = []byte("key")
)

func doRequestAndVerify(d *ConiksDirectory, cc *ConsistencyChecks,
	requestType int, name string) error {
	switch requestType {
	case RegistrationType:
		request := &RegistrationRequest{
			Username: name,
			Key:      key,
		}
		res, _ := d.Register(request)
		return cc.HandleResponse(requestType, res, name, key)
	case KeyLookupType:
		request := &KeyLookupRequest{
			Username: name,
		}
		res, _ := d.KeyLookup(request)
		return cc.HandleResponse(requestType, res, name, key)
	case MonitoringType:
	case KeyLookupInEpochType:
	}
	panic("Unknown request type")
}

func TestVerifyWithError(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	// modify the pinning STR so that the consistency check should fail.
	str := *(d.LatestSTR())
	str.Signature = append([]byte{}, str.Signature...)
	str.Signature[0]++

	cc := NewCC(&str, true, pk)

	if err := doRequestAndVerify(d, cc, RegistrationType, "alice"); err != ErrorBadSTR {
		t.Fatal("Expect", ErrorBadSTR, "got", err)
	}
}

func TestVerifyRegistrationResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	if doRequestAndVerify(d, cc, RegistrationType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// test error name existed
	// FIXME: Check that we got an ErrorNameExisted
	if doRequestAndVerify(d, cc, RegistrationType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}

	// test error name existed with different key
	res, err := d.Register(&RegistrationRequest{
		Username: "alice",
		Key:      []byte{1, 2, 3},
	})
	if err != ErrorNameExisted {
		t.Fatal("Expect error code", ErrorNameExisted, "got", err)
	}
	// expect a proof of absence since this binding wasn't included in this epoch
	if err := cc.HandleResponse(RegistrationType, res, "alice", key); err != Passed {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 1 {
		t.Fatal("Expect the directory to return a signed promise")
	}

	// re-register in a different epoch
	// Since the fulfilled promise verification would be perform
	// when the client is monitoring, we do _not_ expect a TB's verification here.
	d.Update()

	// FIXME: Check that we got an ErrorNameExisted
	if doRequestAndVerify(d, cc, RegistrationType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}
}

func TestVerifyFullfilledPromise(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	if doRequestAndVerify(d, cc, RegistrationType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}
	if doRequestAndVerify(d, cc, RegistrationType, "bob") != Passed {
		t.Fatal("Unexpected verification result")
	}

	if len(cc.TBs) != 2 {
		t.Fatal("Expect the directory to return signed promises")
	}

	d.Update()

	cc.SavedSTR = d.LatestSTR() // bypass monitoring check

	for i := 0; i < 2; i++ {
		if doRequestAndVerify(d, cc, KeyLookupType, "alice") != Passed {
			t.Error("Unexpected verification result")
		}
	}

	// should contain the TBs of "bob"
	if len(cc.TBs) != 1 || cc.TBs["bob"] == nil {
		t.Error("Expect the directory to insert the binding as promised")
	}
}

func TestVerifyKeyLookupResponseWithTB(t *testing.T) {
	d, pk := NewTestDirectory(t, true)

	cc := NewCC(d.LatestSTR(), true, pk)

	// do lookup first
	if doRequestAndVerify(d, cc, KeyLookupType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}

	// register
	if doRequestAndVerify(d, cc, RegistrationType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}
	// do lookup in the same epoch
	if doRequestAndVerify(d, cc, KeyLookupType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}

	// do lookup in the different epoch
	d.Update()

	cc.SavedSTR = d.LatestSTR() // bypass monitoring check

	if doRequestAndVerify(d, cc, KeyLookupType, "alice") != Passed {
		t.Fatal("Unexpected verification result")
	}

	// test error name not found
	if doRequestAndVerify(d, cc, KeyLookupType, "bob") != Passed {
		t.Fatal("Unexpected verification result")
	}
}
