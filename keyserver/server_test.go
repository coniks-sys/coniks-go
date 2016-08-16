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
		reg := `
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
		rev, err := testutil.NewClient(t, testutil.LocalConnection, []byte(reg))
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
		reg := `
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
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(reg))
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
