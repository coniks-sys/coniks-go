package server

import (
	"bytes"
	"encoding/json"
	"path"
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

// NewTestServer initializes a test CONIKS key server with the given
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
		ServerBaseConfig: &application.ServerBaseConfig{
			Logger: &application.LoggerConfig{
				Environment: "development",
				Path:        path.Join(dir, "coniksserver.log"),
			},
		},
		LoadedHistoryLength: 100,
		Addresses:           addrs,
		Policies: NewPolicies(epDeadline, "", "", vrfKey,
			signKey),
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
	server, teardown := startServer(t, 1, true, "")
	defer teardown()
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR2)
	if server.dir.EpochDeadline() != 1 {
		t.Fatal("Expect the server's policies not change")
	}
	// just to make sure the server's still running normally
	timer := time.NewTimer(1 * time.Second)
	<-timer.C
}

func TestAcceptOutsideRegistrationRequests(t *testing.T) {
	_, teardown := startServer(t, 60, false, "")
	defer teardown()
	rev, err := testutil.NewTCPClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Error(err)
	}
	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Log(string(rev))
		t.Error(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Error("Expect a successful registration", "got", response.Error)
	}
}

func TestBotSendsRegistration(t *testing.T) {
	_, teardown := startServer(t, 60, true, "")
	defer teardown()

	rev, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Log(string(rev))
		t.Fatal(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Fatal("Expect a successful registration", "got", response.Error)
	}
}

func TestSendsRegistrationFromOutside(t *testing.T) {
	_, teardown := startServer(t, 60, true, "")
	defer teardown()

	rev, err := testutil.NewTCPClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ErrMalformedMessage {
		t.Fatalf("Expect error code %d", protocol.ErrMalformedMessage)
	}
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

func TestRegisterDuplicateUserInOneEpoch(t *testing.T) {
	server, teardown := startServer(t, 60, true, "")
	defer teardown()
	r0 := createMultiRegistrationRequests(1)[0]
	r1 := createMultiRegistrationRequests(1)[0]
	rev := server.HandleRequests(r0)
	if rev.Error != protocol.ReqSuccess {
		t.Fatal("Error while submitting registration request")
	}
	rev = server.HandleRequests(r1)
	response, ok := rev.DirectoryResponse.(*protocol.DirectoryProof)
	if !ok {
		t.Fatal("Expect a directory proof response")
	}
	if rev.Error != protocol.ReqNameExisted {
		t.Fatal("Expect error code", protocol.ReqNameExisted)
	}
	if response.STR == nil || response.AP == nil || response.TB == nil {
		t.Fatal("Unexpected response")
	}
	if !bytes.Equal(response.TB.Value, r1.Request.(*protocol.RegistrationRequest).Key) {
		t.Fatal("Unexpect returned TB")
	}
}

func TestRegisterDuplicateUserInDifferentEpoches(t *testing.T) {
	server, teardown := startServer(t, 1, true, "")
	defer teardown()
	r0 := createMultiRegistrationRequests(1)[0]
	rev := server.HandleRequests(r0)
	if rev.Error != protocol.ReqSuccess {
		t.Fatal("Error while submitting registration request")
	}
	timer := time.NewTimer(2 * time.Second)
	<-timer.C
	rev = server.HandleRequests(r0)
	response, ok := rev.DirectoryResponse.(*protocol.DirectoryProof)
	if !ok {
		t.Fatal("Expect a directory proof response")
	}
	if rev.Error != protocol.ReqNameExisted {
		t.Fatal("Expect error code", protocol.ReqNameExisted, "got", rev.Error)
	}
	if response.STR == nil || response.AP == nil || response.TB != nil {
		t.Fatal("Unexpected response")
	}
}

func TestBotSendsLookup(t *testing.T) {
	_, teardown := startServer(t, 60, true, "")
	defer teardown()

	rev, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	rev, err = testutil.NewUnixClientDefault([]byte(keylookupMsg))
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Fatalf("Expect error code %d", protocol.ReqSuccess)
	}
}

func TestRegisterAndLookupInTheSameEpoch(t *testing.T) {
	_, teardown := startServer(t, 60, true, "")
	defer teardown()

	_, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	rev, err := testutil.NewTCPClientDefault([]byte(keylookupMsg))
	if err != nil {
		t.Fatal(err)
	}

	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Fatal("Expect no error", "got", response.Error)
	}
	if response.DirectoryResponse.STR == nil {
		t.Fatal("Expect the latets STR")
	}

	var str testutil.ExpectingSTR
	err = json.Unmarshal(response.DirectoryResponse.STR[0], &str)
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
}

func TestRegisterAndLookup(t *testing.T) {
	server, teardown := startServer(t, 1, true, "")
	defer teardown()

	_, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	server.dir.Update()
	rev, err := testutil.NewTCPClientDefault([]byte(keylookupMsg))
	if err != nil {
		t.Fatal(err)
	}

	var res testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &res)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != protocol.ReqSuccess {
		t.Fatal("Expect no error", "got", res.Error)
	}
	if res.DirectoryResponse.STR == nil {
		t.Fatal("Expect the latets STR")
	}

	var str testutil.ExpectingSTR
	err = json.Unmarshal(res.DirectoryResponse.STR[0], &str)
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
}

func TestKeyLookup(t *testing.T) {
	server, teardown := startServer(t, 60, true, "")
	defer teardown()

	_, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	server.dir.Update()
	rev, err := testutil.NewTCPClientDefault([]byte(keylookupMsg))
	if err != nil {
		t.Fatal(err)
	}

	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Fatal("Expect no error", "got", response.Error)
	}
	if response.DirectoryResponse.STR == nil {
		t.Fatal("Expect the latets STR")
	}

	var str testutil.ExpectingSTR
	err = json.Unmarshal(response.DirectoryResponse.STR[0], &str)
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
}

func TestKeyLookupInEpoch(t *testing.T) {
	server, teardown := startServer(t, 60, true, "")
	defer teardown()

	for i := 0; i < 3; i++ {
		server.dir.Update()
	}
	_, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
	if err != nil {
		t.Fatal(err)
	}

	var keylookupinepochMsg = `
{
    "type": 2,
    "request": {
        "Username": "alice@twitter",
        "Epoch": 1
    }
}
`
	rev, err := testutil.NewTCPClientDefault([]byte(keylookupinepochMsg))
	if err != nil {
		t.Fatal(err)
	}

	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ReqNameNotFound {
		t.Fatal("Expect error", protocol.ReqNameNotFound, "got", response.Error)
	}
	if len(response.DirectoryResponse.STR) != 3 {
		t.Fatal("Expect", 3, "STRs in reponse")
	}
}

func TestMonitoring(t *testing.T) {
	N := 5
	server, teardown := startServer(t, 60, true, "")
	defer teardown()

	res, err := testutil.NewUnixClientDefault([]byte(registrationMsg))
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
        "Username": "alice@twitter",
        "StartEpoch": 1,
        "EndEpoch": 5
    }
}
`
	rev, err := testutil.NewTCPClientDefault([]byte(consistencyCheckMsg))
	if err != nil {
		t.Fatal(err)
	}

	var response testutil.ExpectingDirProofResponse
	err = json.Unmarshal(rev, &response)
	if err != nil {
		t.Fatal(err)
	}
	if response.Error != protocol.ReqSuccess {
		t.Fatal("Expect error", protocol.ReqSuccess, "got", response.Error)
	}
	if len(response.DirectoryResponse.STR) != N ||
		len(response.DirectoryResponse.AP) != len(response.DirectoryResponse.STR) {
		t.Fatal("Expect", N, "STRs/APs in reponse", "got", len(response.DirectoryResponse.STR))
	}
}
