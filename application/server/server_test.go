package server

import (
	"encoding/json"
	"math/rand"
	"path"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/application/testutil"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/protocol"
)

var registrationMsg = `
{
    "type": 0,
    "request": {
        "Username": "alice@twitter",
        "Key": [0,1,2],
        "AllowUnsignedKeychange": true,
        "AllowPublicLookup": true
    }
}
`

var keylookupMsg = `
{
    "type": 1,
    "request": {
        "Username": "alice@twitter"
    }
}
`

func newTestTCPAddress(dir string) *application.ServerAddress {
	return &application.ServerAddress{
		Address:     testutil.PublicConnection,
		TLSCertPath: path.Join(dir, "server.pem"),
		TLSKeyPath:  path.Join(dir, "server.key"),
	}
}

// newTestServer initializes a test CONIKS key server with the given
// epoch deadline, registration bot usage useBot,
// policies path, and directory.
func newTestServer(t *testing.T, epDeadline protocol.Timestamp, useBot bool,
	policiesPath, dir string) (*ConiksServer, *Config) {
	signKey, err := sign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	vrfKey, err := vrf.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	addrs := []*Address{
		&Address{
			ServerAddress:     newTestTCPAddress(dir),
			AllowRegistration: !useBot,
		},
	}
	if useBot {
		addrs = append(addrs, &Address{
			ServerAddress: &application.ServerAddress{
				Address: testutil.LocalConnection,
			},
			AllowRegistration: useBot,
		})
	}

	conf := &Config{
		CommonConfig: &application.CommonConfig{
			Logger: &application.LoggerConfig{
				Environment: "development",
				Path:        path.Join(dir, "coniksserver.log"),
			},
		},
		LoadedHistoryLength: 100,
		Addresses:           addrs,
		Policies: NewPolicies(epDeadline, "", "", vrfKey,
			signKey),
		EpochDeadline: epDeadline,
	}

	return NewConiksServer(conf), conf
}

func startServer(t *testing.T, epDeadline protocol.Timestamp, useBot bool, policiesPath string) (*ConiksServer, func()) {
	dir, teardown := testutil.CreateTLSCertForTest(t)

	server, conf := newTestServer(t, epDeadline, useBot, policiesPath, dir)
	server.Run(conf.Addresses)
	return server, func() {
		server.Shutdown()
		teardown()
	}
}

func TestServerStartStop(t *testing.T) {
	_, teardown := startServer(t, 60, true, "")
	defer teardown()
}

func TestServerReloadPoliciesWithError(t *testing.T) {
	deadline := protocol.Timestamp(rand.Int())
	server, teardown := startServer(t, deadline, true, "")
	defer teardown()
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR2)
	if server.dir.EpochDeadline() != deadline {
		t.Fatal("Expect the server's policies not change")
	}
	// just to make sure the server's still running normally
	timer := time.NewTimer(1 * time.Second)
	<-timer.C
}

func TestRequestPermissions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		useBot      bool
		fromBot     bool
		requestType int
		want        error
	}{
		{"without bot", false, false, protocol.RegistrationType, protocol.ReqSuccess},
		{"use bot and accept registrations from bot", true, true, protocol.RegistrationType, protocol.ReqSuccess},
		{"use bot and reject registrations from client", true, false, protocol.RegistrationType, protocol.ErrMalformedMessage},
		{"use bot and accept other request types from client", true, false, protocol.KeyLookupInEpochType, protocol.ReqNameNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, teardown := startServer(t, 60, tc.useBot, "")
			defer teardown()
			var msg []byte
			if tc.requestType == protocol.RegistrationType {
				msg = []byte(registrationMsg)
			} else {
				msg = []byte(keylookupMsg)
			}
			var rev []byte
			var err error
			if tc.fromBot {
				rev, err = testutil.NewUnixClientDefault(msg)
			} else {
				rev, err = testutil.NewTCPClientDefault(msg)
			}
			if err != nil {
				t.Errorf("Test %s got error %s", tc.name, err)
			}
			var response testutil.ExpectingDirProofResponse
			err = json.Unmarshal(rev, &response)
			if err != nil {
				t.Log(string(rev))
				t.Error(err)
			}
			if got, want := response.Error, tc.want; got != want {
				t.Errorf("Test %s failed, want: %s, got: %s", tc.name, want.Error(), got.Error())
			}
		})
	}
}

func createMultiRegistrationRequests(N uint64) []*protocol.Request {
	var rs []*protocol.Request
	for i := uint64(0); i < N; i++ {
		r := &protocol.Request{
			Type: protocol.RegistrationType,
			Request: &protocol.RegistrationRequest{
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

func TestServerHandlesMultipleRequests(t *testing.T) {
	var N uint64 = 10 // number of requests

	_, teardown := startServer(t, 10, true, "")
	defer teardown()

	rs := createMultiRegistrationRequests(N)
	rsJSON := [][]byte{}
	for _, r := range rs {
		if tmp, err := json.Marshal(r); err != nil {
			t.Fatal(err)
		} else {
			rsJSON = append(rsJSON, tmp)
		}
	}

	var wg sync.WaitGroup
	worker := func(request []byte) {
		defer wg.Done()
		rev, err := testutil.NewUnixClientDefault(request)
		if err != nil {
			t.Error(err)
		}
		var response testutil.ExpectingDirProofResponse
		err = json.Unmarshal(rev, &response)
		if err != nil {
			t.Log(string(rev))
			t.Error(err)
		}
		if got, want := response.Error, protocol.ReqSuccess; got != want {
			t.Errorf("Test failed, want: %s, got: %s", want.Error(), got.Error())
		}
	}

	for i := uint64(0); i < N; i++ {
		request := rsJSON[i]
		wg.Add(1)
		go worker(request)
	}

	wg.Wait()
}

func TestUpdateDirectory(t *testing.T) {
	server, teardown := startServer(t, 1, true, "")
	defer teardown()
	str0 := server.dir.LatestSTR()
	rs := createMultiRegistrationRequests(10)
	for i := range rs {
		req := server.HandleRequests(rs[i])
		if req.Error != protocol.ReqSuccess {
			t.Fatal("Error while submitting registration request number", i, "to server")
		}
	}
	timer := time.NewTimer(1 * time.Second)
	<-timer.C
	str1 := server.dir.LatestSTR()
	if str0.Epoch != 0 || str1.Epoch != 1 || !str1.VerifyHashChain(str0) {
		t.Fatal("Expect next STR in hash chain")
	}
}
