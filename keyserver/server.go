package keyserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/utils"
)

// A ServerConfig contains configuration values
// which are read at initialization time from
// a TOML format configuration file.
type ServerConfig struct {
	// LoadedHistoryLength is the maximum number of
	// snapshots kept in memory.
	LoadedHistoryLength uint64 `toml:"loaded_history_length"`
	// Policies contains the server's CONIKS policies configuration.
	Policies *ServerPolicies `toml:"policies"`
	// Addresses contains the server's connections configuration.
	Addresses      []*Address          `toml:"addresses"`
	Logger         *utils.LoggerConfig `toml:"logger"`
	configFilePath string
}

// An Address describes a server's connection.
// It makes the server connections configurable
// so that a key server implementation can easily
// be run by a first-party identity provider or
// a third-party communication service.
// It supports two types of connections: a TCP connection ("tcp")
// and a Unix socket connection ("unix").
//
// Allowing registration has to be specified explicitly for each connection.
// Other types of requests are allowed by default.
// One can think of a registration as a "write" to a key directory,
// while the other request types are "reads".
// So, by default, addresses are "read-only".
//
// Additionally, TCP connections must use TLS for added security,
// and each is required to specify a TLS certificate and corresponding
// private key.
type Address struct {
	// Address is formatted as a url: scheme://address.
	Address           string `toml:"address"`
	AllowRegistration bool   `toml:"allow_registration,omitempty"`
	// TLSCertPath is a path to the server's TLS Certificate,
	// which has to be set if the connection is TCP.
	TLSCertPath string `toml:"cert,omitempty"`
	// TLSKeyPath is a path to the server's TLS private key,
	// which has to be set if the connection is TCP.
	TLSKeyPath string `toml:"key,omitempty"`
}

// ServerPolicies contains a server's CONIKS policies configuration
// including paths to the VRF private key, the signing private
// key and the epoch deadline value in seconds.
type ServerPolicies struct {
	EpochDeadline protocol.Timestamp `toml:"epoch_deadline"`
	VRFKeyPath    string             `toml:"vrf_key_path"`
	SignKeyPath   string             `toml:"sign_key_path"` // it should be a part of policies, see #47
	vrfKey        vrf.PrivateKey
	signKey       sign.PrivateKey
}

// A ConiksServer represents a CONIKS key server.
// It wraps a ConiksDirectory with a network layer which
// handles requests/responses and their encoding/decoding.
// A ConiksServer also supports concurrent handling of requests and
// a mechanism to update the underlying ConiksDirectory automatically
// at regular time intervals.
type ConiksServer struct {
	logger *utils.Logger

	sync.RWMutex
	dir *protocol.ConiksDirectory

	stop          chan struct{}
	waitStop      sync.WaitGroup
	waitCloseConn sync.WaitGroup

	configFilePath string
	reloadChan     chan os.Signal
	epochTimer     *time.Timer
}

// LoadServerConfig loads the ServerConfig for the server from the
// corresponding config file. It reads the siging key pair and the VRF key
// pair into the ServerConfig instance and updates the path of
// TLS certificate files of each Address to absolute path.
func LoadServerConfig(file string) (*ServerConfig, error) {
	var conf ServerConfig
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

	conf.configFilePath = file
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
func NewConiksServer(conf *ServerConfig) *ConiksServer {
	// create server instance
	server := new(ConiksServer)
	server.logger = utils.NewLogger(conf.Logger)
	server.dir = protocol.NewDirectory(
		conf.Policies.EpochDeadline,
		conf.Policies.vrfKey,
		conf.Policies.signKey,
		conf.LoadedHistoryLength,
		true)
	server.stop = make(chan struct{})
	server.configFilePath = conf.configFilePath
	server.reloadChan = make(chan os.Signal, 1)
	signal.Notify(server.reloadChan, syscall.SIGUSR2)
	server.epochTimer = time.NewTimer(time.Duration(conf.Policies.EpochDeadline) * time.Second)

	return server
}

// Run implements the main functionality of the key server.
// It listens for all declared connections with corresponding
// permissions.
// It also supports hot-reloading the configuration by listening for
// SIGUSR2 signal.
func (server *ConiksServer) Run(addrs []*Address) {
	server.waitStop.Add(1)
	go func() {
		server.epochUpdate()
		server.waitStop.Done()
	}()
	hasRegistrationPerm := false
	for i := 0; i < len(addrs); i++ {
		addr := addrs[i]
		perms := updatePerms(addr)
		hasRegistrationPerm = hasRegistrationPerm || addr.AllowRegistration
		u, err := url.Parse(addr.Address)
		if err != nil {
			panic(err)
		}
		switch u.Scheme {
		case "https":
			mux := http.NewServeMux()
			mux.HandleFunc("/", server.makeHTTPSHandler(perms))
			ln, tlsConfig := resolveAndListen(addr)
			httpSrv := &http.Server{
				Addr:      u.Host,
				Handler:   mux,
				TLSConfig: tlsConfig,
			}
			go func() {
				httpSrv.Serve(ln)
			}()
			server.waitStop.Add(1)
			go func() {
				<-server.stop
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				httpSrv.Shutdown(ctx)
				server.waitStop.Done()
			}()
		case "tcp", "unix":
			ln, tlsConfig := resolveAndListen(addr)
			server.waitStop.Add(1)
			go func() {
				server.handleRequests(ln, tlsConfig, server.makeHandler(perms))
				server.waitStop.Done()
			}()
		}
		verb := "Listening"
		if addr.AllowRegistration {
			verb = "Accepting registrations"
		}
		server.logger.Info(verb, "address", addr.Address)
	}

	if !hasRegistrationPerm {
		server.logger.Warn("None of the addresses permit registration")
	}

	server.waitStop.Add(1)
	go func() {
		server.updatePolicies()
		server.waitStop.Done()
	}()
}

func (server *ConiksServer) epochUpdate() {
	for {
		select {
		case <-server.stop:
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
		case <-server.stop:
			return
		case <-server.reloadChan:
			// read server policies from config file
			conf, err := LoadServerConfig(server.configFilePath)
			if err != nil {
				// error occured while reading server config
				// simply abort the reloading policies process
				server.logger.Error(err.Error())
				return
			}
			server.Lock()
			server.dir.SetPolicies(conf.Policies.EpochDeadline)
			server.Unlock()
			server.logger.Info("Policies reloaded!")
		}
	}
}

func resolveAndListen(addr *Address) (ln net.Listener, tlsConfig *tls.Config) {
	u, err := url.Parse(addr.Address)
	if err != nil {
		panic(err)
	}
	switch u.Scheme {
	case "https":
		cer, err := tls.LoadX509KeyPair(addr.TLSCertPath, addr.TLSKeyPath)
		if err != nil {
			panic(err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
		ln, err = tls.Listen("tcp", u.Host, tlsConfig)
		if err != nil {
			panic(err)
		}
		return
	case "tcp":
		// force to use TLS
		cer, err := tls.LoadX509KeyPair(addr.TLSCertPath, addr.TLSKeyPath)
		if err != nil {
			panic(err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
		tcpaddr, err := net.ResolveTCPAddr(u.Scheme, u.Host)
		if err != nil {
			panic(err)
		}
		ln, err = net.ListenTCP(u.Scheme, tcpaddr)
		if err != nil {
			panic(err)
		}
		return
	case "unix":
		unixaddr, err := net.ResolveUnixAddr(u.Scheme, u.Path)
		if err != nil {
			panic(err)
		}
		ln, err = net.ListenUnix(u.Scheme, unixaddr)
		if err != nil {
			panic(err)
		}
		return
	default:
		panic("Unknown network type")
	}
}

func updatePerms(addr *Address) map[int]bool {
	perms := make(map[int]bool)
	perms[protocol.KeyLookupType] = true
	perms[protocol.KeyLookupInEpochType] = true
	perms[protocol.MonitoringType] = true
	perms[protocol.RegistrationType] = addr.AllowRegistration
	return perms
}

// Shutdown closes all of the server's connections and shuts down the server.
func (server *ConiksServer) Shutdown() error {
	close(server.stop)
	server.waitStop.Wait()
	return nil
}
