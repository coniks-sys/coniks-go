package server

import (
	"fmt"
	"io/ioutil"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
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

// A Config contains configuration values
// which are read at initialization time from
// a TOML format configuration file.
type Config struct {
	*application.ServerBaseConfig
	// LoadedHistoryLength is the maximum number of
	// snapshots kept in memory.
	LoadedHistoryLength uint64 `toml:"loaded_history_length"`
	// Policies contains the server's CONIKS policies configuration.
	Policies *Policies `toml:"policies"`
	// Addresses contains the server's connections configuration.
	Addresses []*Address `toml:"addresses"`
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

// LoadServerConfig loads the ServerConfig for the server from the
// corresponding config file. It reads the siging key pair and the VRF key
// pair into the ServerConfig instance and updates the path of
// TLS certificate files of each Address to absolute path.
func LoadServerConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := utils.ResolvePath(conf.Policies.SignKeyPath, file)
	signKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signKey) != sign.PrivateKeySize {
		return nil, fmt.Errorf("Signing key must be 64 bytes (got %d)", len(signKey))
	}

	// load VRF key
	vrfPath := utils.ResolvePath(conf.Policies.VRFKeyPath, file)
	vrfKey, err := ioutil.ReadFile(vrfPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read VRF key: %v", err)
	}
	if len(vrfKey) != vrf.PrivateKeySize {
		return nil, fmt.Errorf("VRF key must be 64 bytes (got %d)", len(vrfKey))
	}

	conf.ConfigFilePath = file
	conf.Policies.vrfKey = vrfKey
	conf.Policies.signKey = signKey
	// also update path for TLS cert files
	for _, addr := range conf.Addresses {
		addr.TLSCertPath = utils.ResolvePath(addr.TLSCertPath, file)
		addr.TLSKeyPath = utils.ResolvePath(addr.TLSKeyPath, file)
	}
	// logger config
	conf.Logger.Path = utils.ResolvePath(conf.Logger.Path, file)

	return &conf, nil
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
			conf, err := LoadServerConfig(server.ConfigFilePath())
			if err != nil {
				// error occured while reading server config
				// simply abort the reloading policies
				// process
				server.Logger().Error(err.Error())
				return
			}
			server.Lock()
			server.dir.SetPolicies(conf.Policies.EpochDeadline)
			server.Unlock()
			server.Logger().Info("Policies reloaded!")
		}
	}
}
