package server

import (
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
	epochTimer *application.EpochTimer
}

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
	sb := application.NewServerBase(conf.CommonConfig, "Listen",
		perms)

	server := &ConiksServer{
		ServerBase: sb,
		dir: directory.New(
			conf.Policies.EpochDeadline,
			conf.Policies.vrfKey,
			conf.Policies.signKey,
			conf.LoadedHistoryLength,
			true),
		epochTimer: application.NewEpochTimer(conf.EpochDeadline),
	}

	// save the initial STR to be used for initializing auditors
	// FIXME: this saving should happen in protocol/ (i.e., when the
	// server starts and updates), because eventually we'll need
	// persistent storage.
	initSTRPath := utils.ResolvePath(conf.InitSTRPath, conf.Path)
	application.SaveSTR(initSTRPath, server.dir.LatestSTR())

	return server
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
	server.RunInBackground(func() {
		server.EpochUpdate(server.epochTimer, server.dir.Update)
	})

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

	server.RunInBackground(func() {
		server.HotReload(server.updatePolicies)
	})
}

func (server *ConiksServer) updatePolicies() {
	// read server policies from config file
	conf := &Config{}
	if err := conf.Load(server.ConfigInfo()); err != nil {
		// error occured while reading server config
		// simply abort the reloading policies
		// process
		server.Logger().Error(err.Error())
		return
	}
	server.dir.SetPolicies(conf.Policies.EpochDeadline)
	server.Logger().Info("Policies reloaded!")
}
