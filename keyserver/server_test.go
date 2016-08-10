package keyserver

import (
	"encoding/json"
	"os"
	"os/signal"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/utils"
)

func startServer(t *testing.T, kvdb kv.DB, epDeadline merkletree.TimeStamp, policiesPath string) (*ConiksServer, func()) {
	dir, teardown := testutil.CreateTLSCert(t)

	sk, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var loadedHistoryLength uint64 = 100
	var registrationCapacity uint64 = 100

	server := new(ConiksServer)
	server.stop = make(chan struct{})
	server.db = kvdb
	server.policies = &ServerPolicies{EpochDeadline: epDeadline}
	server.policiesFilePath = policiesPath
	server.reloadChan = make(chan os.Signal, 1)
	signal.Notify(server.reloadChan, syscall.SIGUSR2)
	server.epochTimer = time.NewTimer(time.Duration(server.policies.EpochDeadline) * time.Second)
	server.directory = protocol.InitDirectory(epDeadline, vrfKey,
		sk, loadedHistoryLength,
		true, registrationCapacity)

	conf := &ServerConfig{
		Address:             testutil.PublicConnection,
		RegistrationAddress: testutil.LocalConnection,
		TLS: TLSInfo{
			TLSCertPath: path.Join(dir, "server.pem"),
			TLSKeyPath:  path.Join(dir, "server.key"),
		},
	}
	server.RunWithConfig(conf)
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

func TestBotSendsRegistration(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		_, teardown := startServer(t, db, 60, "")
		defer teardown()
		reg := `
{
	"type": 0,
	"request": {
		"username": "alice@twitter",
		"key": "AA==",
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
			Content json.RawMessage
		}
		var response ExpectingResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Type != protocol.RegistrationType {
			t.Fatal("Expect a registration response")
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
		"key": "AA==",
        "allow_unsigned_key_change": true,
        "allow_public_lookup": true
	}
}
`
		rev, err := testutil.NewClient(t, testutil.PublicConnection, []byte(reg))
		if err != nil {
			t.Fatal(err)
		}
		var response protocol.ErrorResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Fatal(err)
		}
		if response.Error != protocol.ErrorMalformedClientMessage {
			t.Fatalf("Expect error code %d", protocol.ErrorMalformedClientMessage)
		}
	})
}

func TestUpdateDirectory(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 1, "")
		defer teardown()
		str0 := server.directory.LatestSTR()
		rs := createMultiRegistrationRequests(10)
		for i := range rs {
			_, err := server.handleRegistrationMessage(rs[i])
			if err != nil {
				t.Fatal("Error while submitting registration request number", i, "to server")
			}
		}
		timer := time.NewTimer(1 * time.Second)
		for {
			select {
			case <-timer.C:
				str1 := server.directory.LatestSTR()
				if str0.Epoch != 0 || str1.Epoch != 1 || !merkletree.VerifyHashChain(str1.PreviousSTRHash, str0.Signature) {
					t.Fatal("Expect next STR in hash chain")
				}
				return
			}
		}
	})
}

func createMultiRegistrationRequests(N uint64) []*protocol.RegistrationRequest {
	var rs []*protocol.RegistrationRequest
	for i := uint64(0); i < N; i++ {
		r := new(protocol.RegistrationRequest)
		r.Username = "user" + string(i)
		r.Key = "key" + string(i)
		r.AllowPublicLookup = true
		r.AllowUnsignedKeychange = true
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
		_, err := server.handleRegistrationMessage(r0)
		if err != nil {
			t.Fatal("Error while submitting registration request")
		}
		_, err = server.handleRegistrationMessage(r1)
		if err != protocol.ErrorNameExisted.Error() {
			t.Fatal("Expect error code", protocol.ErrorNameExisted)
		}
	})
}

func TestRegisterDuplicateUserInDifferentEpoches(t *testing.T) {
	util.WithDB(func(db kv.DB) {
		server, teardown := startServer(t, db, 2, "")
		defer teardown()
		r0 := createMultiRegistrationRequests(1)[0]
		_, err := server.handleRegistrationMessage(r0)
		if err != nil {
			t.Fatal("Error while submitting registration request")
		}
		time.Sleep(3 * time.Second)
		r1 := createMultiRegistrationRequests(1)[0]
		_, err = server.handleRegistrationMessage(r1)
		if err != protocol.ErrorNameExisted.Error() {
			t.Fatal("Expect error code", protocol.ErrorNameExisted)
		}
	})
}
