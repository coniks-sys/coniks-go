package keyserver

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/storage/kv/leveldbkv"
	"github.com/coniks-sys/coniks-go/utils"
)

type ServerConfig struct {
	configFilePath      string
	DatabasePath        string          `toml:"database"`
	LoadedHistoryLength uint64          `toml:"loaded_history_length"`
	Policies            *ServerPolicies `toml:"policies"`
	Addresses           []*Address      `toml:"addresses"`
}

type Address struct {
	Address           string `toml:"address"`
	AllowRegistration bool   `toml:"allow_registration,omitempty"`
	TLSCertPath       string `toml:"cert,omitempty"`
	TLSKeyPath        string `toml:"key,omitempty"`
}

type ServerPolicies struct {
	EpochDeadline protocol.Timestamp `toml:"epoch_deadline"`
	VRFKeyPath    string             `toml:"vrf_key_path"`
	SignKeyPath   string             `toml:"sign_key_path"` // it should be a part of policies, see #47
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
}

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
	// also update path for db & TLS cert files
	conf.DatabasePath = utils.ResolvePath(conf.DatabasePath, file)
	for _, addr := range conf.Addresses {
		addr.TLSCertPath = utils.ResolvePath(addr.TLSCertPath, file)
		addr.TLSKeyPath = utils.ResolvePath(addr.TLSKeyPath, file)
	}
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

func (server *ConiksServer) Run(addrs []*Address) {
	server.waitStop.Add(1)
	go func() {
		server.EpochUpdate()
		server.waitStop.Done()
	}()

	hasRegistrationPerm := false
	for i := 0; i < len(addrs); i++ {
		addr := addrs[i]
		hasRegistrationPerm = hasRegistrationPerm || addr.AllowRegistration
		ln, tlsConfig, perms := resolveAndListen(addr)
		server.waitStop.Add(1)
		go func() {
			server.handleRequests(ln, tlsConfig, server.makeHandler(perms))
			server.waitStop.Done()
		}()
	}

	if !hasRegistrationPerm {
		log.Println("[Warning] None of the addresses permit registration")
	}

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
			server.dir.SetPolicies(conf.Policies.EpochDeadline)
			server.Unlock()
			log.Println("Policies reloaded!")
		}
	}
}

func resolveAndListen(addr *Address) (ln net.Listener,
	tlsConfig *tls.Config,
	perms map[int]bool) {
	perms = make(map[int]bool)
	perms[protocol.KeyLookupType] = true
	perms[protocol.KeyLookupInEpochType] = true
	perms[protocol.MonitoringType] = true
	perms[protocol.RegistrationType] = addr.AllowRegistration

	u, err := url.Parse(addr.Address)
	if err != nil {
		panic(err)
	}
	switch u.Scheme {
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
