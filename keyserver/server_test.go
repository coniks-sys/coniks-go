package keyserver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	"github.com/coniks-sys/coniks-go/merkletree"
	. "github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

var registrationMsg = `
{
    "type": 0,
    "request": {
        "username": "alice@twitter",
        "key": [0,1,2],
        "allow_unsigned_key_change": true,
        "allow_public_lookup": true
    }
}
`

var keylookupMsg = `
{
    "type": 1,
    "request": {
        "username": "alice@twitter"
    }
}
`

func startServer(t *testing.T, kvdb kv.DB, epDeadline merkletree.TimeStamp, policiesPath string) (*ConiksServer, func()) {
	dir, teardown := testutil.CreateTLSCertForTest(t)

	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	conf := &ServerConfig{
		DatabasePath:        path.Join(dir, "coniks.db"),
		LoadedHistoryLength: 100,
		TLS: &TLSConnection{
			PublicAddress: testutil.PublicConnection,
			LocalAddress:  testutil.LocalConnection,
			TLSCertPath:   path.Join(dir, "server.pem"),
			TLSKeyPath:    path.Join(dir, "server.key"),
		},
		Policies: &ServerPolicies{
			EpochDeadline: epDeadline,
			vrfKey:        vrfKey,
			signKey:       signKey,
		},
	}

	server := NewConiksServer(conf)
	server.db = kvdb
	server.Run(conf.TLS)
	return server, func() {
		server.Shutdown()
		teardown()
	}
}

func TestServerStartStop(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()
	})
}

func TestServerReloadPoliciesWithError(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()
		syscall.Kill(syscall.Getpid(), syscall.SIGUSR2)
		if server.dir.EpochDeadline() != 1 {
			t.Fatal("Expect the server's policies not change")
		}
		// just to make sure the server's still running normally
		timer := time.NewTimer(1 * time.Second)
		<-timer.C
	})
}

func TestBotSendsRegistration(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()

		rev, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		type ExpectingResponse struct {
			Type    int
			Error   ErrorCode
			Content json.RawMessage
		}
		var response ExpectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Log(string(rev))
			t.Fatal(err)
		}
		if response.Type != RegistrationType {
			t.Fatal("Expect a registration response")
		}
		if response.Error != Success {
			t.Fatal("Expect a successful registration", "got", response.Error)
		}
	})
}

func TestSendsRegistrationFromOutside(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()

		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}
		var response ErrorResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != ErrorMalformedClientMessage {
			t.Fatalf("Expect error code %d", ErrorMalformedClientMessage)
		}
	})
}

func TestUpdateDirectory(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()
		str0 := server.dir.LatestSTR()
		rs := createMultiRegistrationRequests(10)
		for i := range rs {
			_, err := server.dir.HandleOps(rs[i])
			if err != Success {
				t.Fatal("Error while submitting registration request number", i, "to server")
			}
		}
		timer := time.NewTimer(1 * time.Second)
		<-timer.C
		str1 := server.dir.LatestSTR()
		if str0.Epoch != 0 || str1.Epoch != 1 || !merkletree.VerifyHashChain(str1.PreviousSTRHash, str0.Signature) {
			t.Fatal("Expect next STR in hash chain")
		}
	})
}

func createMultiRegistrationRequests(N uint64) []*Request {
	var rs []*Request
	for i := uint64(0); i < N; i++ {
		r := &Request{
			Type: RegistrationType,
			Request: &RegistrationRequest{
				Username:               "user" + string(i),
				Key:                    []byte("key" + string(i)),
				AllowPublicLookup:      true,
				AllowUnsignedKeychange: true,
			},
		}
		rs = append(rs, r)
	}
	return rs
}

func TestRegisterDuplicateUserInOneEpoch(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 60, "")
		defer teardown()
		r0 := createMultiRegistrationRequests(1)[0]
		r1 := createMultiRegistrationRequests(1)[0]
		_, err := server.dir.HandleOps(r0)
		if err != Success {
			t.Fatal("Error while submitting registration request")
		}
		rev, err := server.dir.HandleOps(r1)
		response, ok := rev.(*DirectoryProof)
		if !ok {
			t.Fatal("Expect a directory proof response")
		}
		if err != ErrorNameExisted ||
			response.Error != ErrorNameExisted {
			t.Fatal("Expect error code", ErrorNameExisted)
		}
		if response.STR == nil || response.AP == nil || response.TB == nil {
			t.Fatal("Unexpected response")
		}
		if !bytes.Equal(response.TB.Value, r1.Request.(*RegistrationRequest).Key) {
			t.Fatal("Unexpect returned TB")
		}
	})
}

func TestRegisterDuplicateUserInDifferentEpoches(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()
		r0 := createMultiRegistrationRequests(1)[0]
		_, err := server.dir.HandleOps(r0)
		if err != Success {
			t.Fatal("Error while submitting registration request")
		}
		timer := time.NewTimer(2 * time.Second)
		<-timer.C
		rev, err := server.dir.HandleOps(r0)
		response, ok := rev.(*DirectoryProof)
		if !ok {
			t.Fatal("Expect a directory proof response")
		}
		if err != ErrorNameExisted ||
			response.Error != ErrorNameExisted {
			t.Fatal("Expect error code", ErrorNameExisted, "got", err)
		}
		if response.STR == nil || response.AP == nil || response.TB != nil {
			t.Fatal("Unexpected response")
		}
	})
}

func TestBotSendsLookup(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()

		rev, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		rev, err = testutil.NewClient(t, testutil.LocalConnection, []byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}
		var response ErrorResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != ErrorMalformedClientMessage {
			t.Fatalf("Expect error code %d", ErrorMalformedClientMessage)
		}
	})
}

func TestRegisterAndLookupInTheSameEpoch(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()

		_, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		type expectingResponse struct {
			Type  int
			Error ErrorCode
			AP    json.RawMessage
			STR   json.RawMessage
			TB    json.RawMessage
		}
		var response expectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != KeyLookupType {
			t.Fatal("Expect a key lookup response", "got", response.Type)
		}
		if response.Error != Success {
			t.Fatal("Expect no error", "got", response.Error)
		}
		if response.STR == nil {
			t.Fatal("Expect the latets STR")
		}
		type expectingSTR struct {
			Epoch uint64
			json.RawMessage
		}
		var str expectingSTR
		err = json.Unmarshal(response.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch != 0 {
			t.Fatal("Expect STR with epoch", 0)
		}
		if response.AP == nil {
			t.Fatal("Expect a proof of absence")
		}
		if response.TB == nil {
			t.Fatal("Expect a TB")
		}
	})
}

func TestRegisterAndLookup(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()

		_, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		server.dir.Update()
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		type expectingResponse struct {
			Type  int
			Error ErrorCode
			AP    json.RawMessage
			STR   json.RawMessage
			TB    json.RawMessage
		}
		var response expectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != KeyLookupType {
			t.Fatal("Expect a key lookup response", "got", response.Type)
		}
		if response.Error != Success {
			t.Fatal("Expect no error", "got", response.Error)
		}
		if response.STR == nil {
			t.Fatal("Expect the latets STR")
		}
		type expectingSTR struct {
			Epoch uint64
		}
		var str expectingSTR
		err = json.Unmarshal(response.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch == 0 {
			t.Fatal("Expect STR with epoch > 0")
		}
		if response.AP == nil {
			t.Fatal("Expect a proof of inclusion")
		}
		if response.TB != nil {
			t.Fatal("Expect returned TB is nil")
		}
	})
}

func TestKeyLookup(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 60, "")
		defer teardown()

		_, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		server.dir.Update()
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		type expectingResponse struct {
			Type  int
			Error ErrorCode
			AP    json.RawMessage
			STR   json.RawMessage
			TB    json.RawMessage
		}
		var response expectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != KeyLookupType {
			t.Fatal("Expect a key lookup response", "got", response.Type)
		}
		if response.Error != Success {
			t.Fatal("Expect no error", "got", response.Error)
		}
		if response.STR == nil {
			t.Fatal("Expect the latets STR")
		}
		type expectingSTR struct {
			Epoch uint64
		}
		var str expectingSTR
		err = json.Unmarshal(response.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch == 0 {
			t.Fatal("Expect STR with epoch > 0")
		}
		if response.AP == nil {
			t.Fatal("Expect a proof of inclusion")
		}
		if response.TB != nil {
			t.Fatal("Expect returned TB is nil")
		}
	})
}

func TestKeyLookupInEpoch(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 60, "")
		defer teardown()

		for i := 0; i < 3; i++ {
			server.dir.Update()
		}
		_, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		var keylookupinepochMsg = `
{
    "type": 2,
    "request": {
        "username": "alice@twitter",
        "epoch": 1,
        "limit": 4
    }
}
`
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(keylookupinepochMsg))
		if err != nil {
			t.Fatal(err)
		}

		type expectingResponse struct {
			Type  int
			Error ErrorCode
			AP    json.RawMessage
			STR   []json.RawMessage
		}
		var response expectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != KeyLookupInEpochType {
			t.Fatal("Expect a key lookup in epoch response", "got", response.Type)
		}
		if response.Error != ErrorNameNotFound {
			t.Fatal("Expect error", ErrorNameNotFound, "got", response.Error)
		}
		if len(response.STR) != 3 {
			t.Fatal("Expect", 3, "STRs in reponse")
		}
	})
}

func TestMonitoring(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		N := 5
		server, teardown := startServer(t, db, 60, "")
		defer teardown()

		res, err := testutil.NewClient(t, testutil.LocalConnection, []byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		// get the STR from the response
		type registrationResponse struct {
			STR json.RawMessage
		}
		var regResponse registrationResponse
		if err := json.Unmarshal(res, &regResponse); err != nil {
			t.Fatal(err)
		}
		latestSTR, _, _ := getSTRFromResponse(t, regResponse.STR)

		for i := 0; i < N; i++ {
			server.dir.Update()
		}

		var consistencyCheckMsg = `
{
    "type": 3,
    "request": {
        "username": "alice@twitter",
        "start_epoch": 1,
        "end_epoch": 5
    }
}
`
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(consistencyCheckMsg))
		if err != nil {
			t.Fatal(err)
		}

		type expectingResponse struct {
			Type  int
			Error ErrorCode
			AP    []json.RawMessage
			STR   []json.RawMessage
		}
		var response expectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != MonitoringType {
			t.Fatal("Expect a consistency check response", "got", response.Type)
		}
		if response.Error != Success {
			t.Fatal("Expect error", Success, "got", response.Error)
		}
		if len(response.STR) != N || len(response.AP) != len(response.STR) {
			t.Fatal("Expect", N, "STRs/APs in reponse", "got", len(response.STR))
		}

		for _, i := range response.STR {
			sig, prevHash, ep := getSTRFromResponse(t, i)
			if !merkletree.VerifyHashChain(prevHash, latestSTR) {
				t.Fatal("Cannot verify hash chain at", ep)
			}
			latestSTR = sig
		}
	})
}

func getSTRFromResponse(t *testing.T, msg []byte) ([]byte, []byte, uint64) {
	type STR struct {
		Epoch           uint64
		PreviousSTRHash string
		Signature       string
	}
	var str STR
	if err := json.Unmarshal(msg, &str); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(str.Signature)
	if err != nil {
		t.Fatal(err)
	}
	prevHash, err := base64.StdEncoding.DecodeString(str.PreviousSTRHash)
	if err != nil {
		t.Fatal(err)
	}
	return sig, prevHash, str.Epoch
}
