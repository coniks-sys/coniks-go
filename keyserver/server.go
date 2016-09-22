package keyserver

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/storage/kv/leveldbkv"
	"github.com/coniks-sys/coniks-go/utils"
)

type ServerConfig struct {
	configFilePath      string
	DatabasePath        string          `toml:"database"`
	LoadedHistoryLength uint64          `toml:"loaded_history_length"`
	Policies            *ServerPolicies `toml:"policies"`
	TLS                 *TLSConnection  `toml:"tls"`
}

type TLSConnection struct {
	PublicAddress string `toml:"public_address"` // address:port
	LocalAddress  string `toml:"local_address"`  // unix socket
	TLSCertPath   string `toml:"cert"`
	TLSKeyPath    string `toml:"key"`
}

type ServerPolicies struct {
	EpochDeadline merkletree.TimeStamp `toml:"epoch_deadline"`
	VRFKeyPath    string               `toml:"vrf_key_path"`
	SignKeyPath   string               `toml:"sign_key_path"` // it should be a part of policies, see #47
	vrfKey        vrf.PrivateKey
	signKey       sign.PrivateKey
}

type ConiksServer struct {
	sync.RWMutex
	dir *protocol.ConiksDirectory

	stop          chan struct{}
	waitStop      sync.WaitGroup
	waitCloseConn sync.WaitGroup

	db kv.DB // TODO: it is a placeholer for issue #37

	configFilePath string
	reloadChan     chan os.Signal
	epochTimer     *time.Timer
	tlsConfig      *tls.Config
}

func LoadServerConfig(file string) (*ServerConfig, error) {
	var conf ServerConfig
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := util.ResolvePath(conf.Policies.SignKeyPath, file)
	signKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signKey) != sign.PrivateKeySize {
		return nil, fmt.Errorf("Signing key must be 64 bytes (got %d)", len(signKey))
	}

	// load VRF key
	vrfPath := util.ResolvePath(conf.Policies.VRFKeyPath, file)
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
	// also update path for db & TLS cert files
	conf.DatabasePath = util.ResolvePath(conf.DatabasePath, file)
	conf.TLS.TLSCertPath = util.ResolvePath(conf.TLS.TLSCertPath, file)
	conf.TLS.TLSKeyPath = util.ResolvePath(conf.TLS.TLSKeyPath, file)

	return &conf, nil
}

func NewConiksServer(conf *ServerConfig) *ConiksServer {
	// open db
	kvdb := leveldbkv.OpenDB(conf.DatabasePath)

	// create server instance
	server := new(ConiksServer)
	server.dir = protocol.NewDirectory(
		conf.Policies.EpochDeadline,
		conf.Policies.vrfKey,
		conf.Policies.signKey,
		conf.LoadedHistoryLength,
		true)
	server.stop = make(chan struct{})
	server.db = kvdb
	server.configFilePath = conf.configFilePath
	server.reloadChan = make(chan os.Signal, 1)
	signal.Notify(server.reloadChan, syscall.SIGUSR2)
	server.epochTimer = time.NewTimer(time.Duration(conf.Policies.EpochDeadline) * time.Second)

	return server
}

func (server *ConiksServer) Run(tc *TLSConnection) {
	server.waitStop.Add(1)
	go func() {
		server.EpochUpdate()
		server.waitStop.Done()
	}()

	// Setup server public connection
	// Setup the TLS config for public connection
	cer, err := tls.LoadX509KeyPair(tc.TLSCertPath, tc.TLSKeyPath)
	if err != nil {
		panic(err)
	}
	server.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cer}}
	addr, err := net.ResolveTCPAddr("tcp", tc.PublicAddress)
	if err != nil {
		panic(err)
	}
	publicLn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}

	// Setup server local connection
	scheme := "unix"
	unixaddr, err := net.ResolveUnixAddr(scheme, tc.LocalAddress)
	if err != nil {
		panic(err)
	}
	localLn, err := net.ListenUnix(scheme, unixaddr)
	if err != nil {
		panic(err)
	}

	// acceptable types for public connection
	publicTypes := make(map[int]bool)
	publicTypes[protocol.KeyLookupType] = true
	publicTypes[protocol.KeyLookupInEpochType] = true
	publicTypes[protocol.MonitoringType] = true
	server.waitStop.Add(1)
	go func() {
		server.listenForRequests(publicLn, server.makeHandler(publicTypes))
		server.waitStop.Done()
	}()

	// acceptable types for local connection
	localTypes := make(map[int]bool)
	localTypes[protocol.RegistrationType] = true
	server.waitStop.Add(1)
	go func() {
		server.listenForRequests(localLn, server.makeHandler(localTypes))
		server.waitStop.Done()
	}()

	server.waitStop.Add(1)
	go func() {
		server.updatePolicies()
		server.waitStop.Done()
	}()
}

func (server *ConiksServer) EpochUpdate() {
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

func (server *ConiksServer) Shutdown() error {
	close(server.stop)
	server.waitStop.Wait()
	return server.db.Close()
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
				log.Println(err)
				// error occured while reading server config
				// simply abort the reloading policies process
				return
			}
			server.Lock()
			server.dir.SetPolicies(conf.Policies.EpochDeadline, conf.Policies.vrfKey)
			server.Unlock()
			log.Println("Policies reloaded!")
		}
	}
}
