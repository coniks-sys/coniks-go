package keyserver

import (
	"bytes"
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

		rev, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		var response testutil.ExpectingDirProofResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Log(string(rev))
			t.Fatal(err)
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

		rev, err := testutil.NewTCPClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}
		var response Response
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
			_, err := handleOps(server.dir, rs[i])
			if err != Success {
				t.Fatal("Error while submitting registration request number", i, "to server")
			}
		}
		timer := time.NewTimer(1 * time.Second)
		<-timer.C
		str1 := server.dir.LatestSTR()
		if str0.Epoch != 0 || str1.Epoch != 1 || !str1.VerifyHashChain(str0.Signature) {
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
		_, err := handleOps(server.dir, r0)
		if err != Success {
			t.Fatal("Error while submitting registration request")
		}
		rev, err := handleOps(server.dir, r1)
		response, ok := rev.DirectoryResponse.(*DirectoryProof)
		if !ok {
			t.Fatal("Expect a directory proof response")
		}
		if err != ErrorNameExisted ||
			rev.Error != ErrorNameExisted {
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
		_, err := handleOps(server.dir, r0)
		if err != Success {
			t.Fatal("Error while submitting registration request")
		}
		timer := time.NewTimer(2 * time.Second)
		<-timer.C
		rev, err := handleOps(server.dir, r0)
		response, ok := rev.DirectoryResponse.(*DirectoryProof)
		if !ok {
			t.Fatal("Expect a directory proof response")
		}
		if err != ErrorNameExisted ||
			rev.Error != ErrorNameExisted {
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

		rev, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		rev, err = testutil.NewUnixClient([]byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}
		var response Response
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

		_, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		rev, err := testutil.NewTCPClient([]byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		var response testutil.ExpectingDirProofResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != Success {
			t.Fatal("Expect no error", "got", response.Error)
		}
		if response.DirectoryResponse.STR == nil {
			t.Fatal("Expect the latets STR")
		}

		var str testutil.ExpectingSTR
		err = json.Unmarshal(response.DirectoryResponse.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch != 0 {
			t.Fatal("Expect STR with epoch", 0)
		}
		if response.DirectoryResponse.AP == nil {
			t.Fatal("Expect a proof of absence")
		}
		if response.DirectoryResponse.TB == nil {
			t.Fatal("Expect a TB")
		}
	})
}

func TestRegisterAndLookup(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()

		_, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		server.dir.Update()
		rev, err := testutil.NewTCPClient([]byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		var res testutil.ExpectingDirProofResponse
		err = json.Unmarshal(rev, &res)
		if err != nil {
			t.Fatal(err)
		}
		if res.Error != Success {
			t.Fatal("Expect no error", "got", res.Error)
		}
		if res.DirectoryResponse.STR == nil {
			t.Fatal("Expect the latets STR")
		}

		var str testutil.ExpectingSTR
		err = json.Unmarshal(res.DirectoryResponse.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch == 0 {
			t.Fatal("Expect STR with epoch > 0")
		}
		if res.DirectoryResponse.AP == nil {
			t.Fatal("Expect a proof of inclusion")
		}
		if res.DirectoryResponse.TB != nil {
			t.Fatal("Expect returned TB is nil")
		}
	})
}

func TestKeyLookup(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 60, "")
		defer teardown()

		_, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		server.dir.Update()
		rev, err := testutil.NewTCPClient([]byte(keylookupMsg))
		if err != nil {
			t.Fatal(err)
		}

		var response testutil.ExpectingDirProofResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != Success {
			t.Fatal("Expect no error", "got", response.Error)
		}
		if response.DirectoryResponse.STR == nil {
			t.Fatal("Expect the latets STR")
		}

		var str testutil.ExpectingSTR
		err = json.Unmarshal(response.DirectoryResponse.STR, &str)
		if err != nil {
			t.Fatal(err)
		}
		if str.Epoch == 0 {
			t.Fatal("Expect STR with epoch > 0")
		}
		if response.DirectoryResponse.AP == nil {
			t.Fatal("Expect a proof of inclusion")
		}
		if response.DirectoryResponse.TB != nil {
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
		_, err := testutil.NewUnixClient([]byte(registrationMsg))
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
		rev, err := testutil.NewTCPClient([]byte(keylookupinepochMsg))
		if err != nil {
			t.Fatal(err)
		}

		var response testutil.ExpectingDirProofsResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != ErrorNameNotFound {
			t.Fatal("Expect error", ErrorNameNotFound, "got", response.Error)
		}
		if len(response.DirectoryResponse.STR) != 3 {
			t.Fatal("Expect", 3, "STRs in reponse")
		}
	})
}

func TestMonitoring(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		N := 5
		server, teardown := startServer(t, db, 60, "")
		defer teardown()

		res, err := testutil.NewUnixClient([]byte(registrationMsg))
		if err != nil {
			t.Fatal(err)
		}

		var regResponse testutil.ExpectingDirProofResponse
		if err := json.Unmarshal(res, &regResponse); err != nil {
			t.Fatal(err)
		}

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
		rev, err := testutil.NewTCPClient([]byte(consistencyCheckMsg))
		if err != nil {
			t.Fatal(err)
		}

		var response testutil.ExpectingDirProofsResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != Success {
			t.Fatal("Expect error", Success, "got", response.Error)
		}
		if len(response.DirectoryResponse.STR) != N ||
			len(response.DirectoryResponse.AP) != len(response.DirectoryResponse.STR) {
			t.Fatal("Expect", N, "STRs/APs in reponse", "got", len(response.DirectoryResponse.STR))
		}
	})
}
