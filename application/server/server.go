package server

import (
	"time"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/directory"
	"github.com/coniks-sys/coniks-go/utils"
)

// An Address describes a server's connection.
// It makes the server connections configurable
// so that a key server implementation can easily
// be run by a first-party identity provider or
// a third-party communication service.
//
// Allowing registration has to be specified explicitly for each connection.
// Other types of requests are allowed by default.
// One can think of a registration as a "write" to a key directory,
// while the other request types are "reads".
// So, by default, addresses are "read-only".
type Address struct {
	*application.ServerAddress
	AllowRegistration bool `toml:"allow_registration,omitempty"`
}

// A ConiksServer represents a CONIKS key server.
// It wraps a ConiksDirectory with a network layer which
// handles requests/responses and their encoding/decoding.
// A ConiksServer also supports concurrent handling of requests and
// a mechanism to update the underlying ConiksDirectory automatically
// at regular time intervals.
type ConiksServer struct {
	*application.ServerBase
	dir        *directory.ConiksDirectory
	epochTimer *time.Timer
}

var _ application.Server = (*ConiksServer)(nil)

// NewConiksServer creates a new reference implementation of
// a CONIKS key server.
func NewConiksServer(conf *Config) *ConiksServer {
	// determine this server's request permissions
	perms := make(map[*application.ServerAddress]map[int]bool)

	for i := 0; i < len(conf.Addresses); i++ {
		addr := conf.Addresses[i]
		perms[addr.ServerAddress] = make(map[int]bool)
		perms[addr.ServerAddress][protocol.KeyLookupType] = true
		perms[addr.ServerAddress][protocol.KeyLookupInEpochType] = true
		perms[addr.ServerAddress][protocol.MonitoringType] = true
		perms[addr.ServerAddress][protocol.RegistrationType] = addr.AllowRegistration
	}

	// create server instance
	sb := application.NewServerBase(conf.ServerBaseConfig, "Listen",
		perms)

	server := &ConiksServer{
		ServerBase: sb,
		dir: directory.New(
			conf.Policies.EpochDeadline,
			conf.Policies.vrfKey,
			conf.Policies.signKey,
			conf.LoadedHistoryLength,
			true),
		epochTimer: time.NewTimer(time.Duration(conf.Policies.EpochDeadline) * time.Second),
	}

	// save the initial STR to be used for initializing auditors
	initSTRPath := utils.ResolvePath(conf.InitSTRPath,
		conf.ConfigFilePath)
	application.SaveSTR(initSTRPath, server.dir.LatestSTR())

	return server
}

// EpochUpdate runs a CONIKS key server's directory epoch update procedure.
func (server *ConiksServer) EpochUpdate() {
	server.epochUpdate()
	server.WaitStopDone()
}

// ConfigHotReload implements hot-reloading the configuration by
// listening for SIGUSR2 signal.
func (server *ConiksServer) ConfigHotReload() {
	server.updatePolicies()
	server.WaitStopDone()
}

// HandleRequests validates the request message and passes it to the
// appropriate operation handler according to the request type.
func (server *ConiksServer) HandleRequests(req *protocol.Request) *protocol.Response {
	switch req.Type {
	case protocol.RegistrationType:
		if msg, ok := req.Request.(*protocol.RegistrationRequest); ok {
			return server.dir.Register(msg)
		}
	case protocol.KeyLookupType:
		if msg, ok := req.Request.(*protocol.KeyLookupRequest); ok {
			return server.dir.KeyLookup(msg)
		}
	case protocol.KeyLookupInEpochType:
		if msg, ok := req.Request.(*protocol.KeyLookupInEpochRequest); ok {
			return server.dir.KeyLookupInEpoch(msg)
		}
	case protocol.MonitoringType:
		if msg, ok := req.Request.(*protocol.MonitoringRequest); ok {
			return server.dir.Monitor(msg)
		}
	}

	return protocol.NewErrorResponse(protocol.ErrMalformedMessage)
}

// Run implements the main functionality of the key server.
// It listens for all declared connections with corresponding
// permissions.
func (server *ConiksServer) Run(addrs []*Address) {
	server.WaitStopAdd()
	go server.EpochUpdate()

	hasRegistrationPerm := false
	for i := 0; i < len(addrs); i++ {
		addr := addrs[i]
		hasRegistrationPerm = hasRegistrationPerm || addr.AllowRegistration
		if addr.AllowRegistration {
			server.Verb = "Accepting registrations"
		}

		server.ListenAndHandle(addr.ServerAddress, server.HandleRequests)
	}

	if !hasRegistrationPerm {
		server.Logger().Warn("None of the addresses permit registration")
	}

	server.WaitStopAdd()
	go server.ConfigHotReload()
}

func (server *ConiksServer) epochUpdate() {
	for {
		select {
		case <-server.Stop():
			return
		case <-server.epochTimer.C:
			server.Lock()
			server.dir.Update()
			server.epochTimer.Reset(time.Duration(server.dir.EpochDeadline()) * time.Second)
			server.Unlock()
		}
	}
}

func (server *ConiksServer) updatePolicies() {
	for {
		select {
		case <-server.Stop():
			return
		case <-server.ReloadChan():
			// read server policies from config file
			tmp, err := application.LoadConfig(server.ConfigFilePath())
			if err != nil {
				// error occured while reading server config
				// simply abort the reloading policies
				// process
				server.Logger().Error(err.Error())
				return
			}
			conf := tmp.(*Config)
			server.Lock()
			server.dir.SetPolicies(conf.Policies.EpochDeadline)
			server.Unlock()
			server.Logger().Info("Policies reloaded!")
		}
	}
}
