package keyserver

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/merkletree"
	"github.com/coniks-sys/coniks-go/protocol"
)

type ServerConfig struct {
	SigningKeyPath       string  `toml:"signing_key"`
	Address              string  `toml:"address"` // address:port
	LoadedHistoryLength  uint64  `toml:"loaded_history_length"`
	RegistrationCapacity uint64  `toml:"registration_capacity"`
	PoliciesPath         string  `toml:"policies"`
	TLS                  tlsInfo `toml:"tls"`
}

type tlsInfo struct {
	TLSCertPath string `toml:"cert"`
	TLSKeyPath  string `toml:"key"`
}

type ConiksServer struct {
	sync.Mutex
	directory *protocol.ConiksDirectory
	tbs       map[string]*merkletree.TemporaryBinding

	stop     chan struct{}
	waitStop sync.WaitGroup

	secretKey crypto.SigningKey

	policies         merkletree.Policies
	policiesFilePath string
	policiesMutex    sync.Mutex
	reloadChan       chan os.Signal
	epochTimer       *time.Timer
}

func LoadServerConfig(path string) *ServerConfig {
	var conf ServerConfig
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		log.Fatalf("Failed to load config: %v", err)
		return nil
	}
	return &conf
}

func New(conf *ServerConfig) *ConiksServer {
	// load signing key
	skBytes, err := ioutil.ReadFile(conf.SigningKeyPath)
	if err != nil {
		log.Fatalf("Cannot read signing key: %v", err)
		return nil
	}
	if len(skBytes) != crypto.PrivateKeySize {
		log.Fatalf("Signing key must be 64 bytes (got %d)", len(skBytes))
		return nil
	}

	sk := make([]byte, crypto.PrivateKeySize)
	copy(sk, skBytes[:crypto.PrivateKeySize])

	// read server policies
	p, err := readPolicies(conf.PoliciesPath)
	if err != nil {
		log.Fatalf("Cannot read policies config: %v", err)
		return nil
	}
	policies := merkletree.NewPolicies(p.EpochDeadline, &p.VRFKey)

	// create server instance
	server := new(ConiksServer)
	server.stop = make(chan struct{})
	server.secretKey = sk
	server.policies = policies
	server.policiesFilePath = conf.PoliciesPath
	server.reloadChan = make(chan os.Signal, 1)
	signal.Notify(server.reloadChan, syscall.SIGUSR2)
	server.epochTimer = time.NewTimer(time.Duration(policies.EpDeadline()) * time.Second)
	server.directory = protocol.InitDirectory(policies, sk, conf.LoadedHistoryLength)
	server.tbs = make(map[string]*merkletree.TemporaryBinding, conf.RegistrationCapacity)

	return server
}

func (server *ConiksServer) RunWithConfig(conf *ServerConfig) {
	server.waitStop.Add(1)
	go server.EpochUpdate()

	// server listener
	cer, err := tls.LoadX509KeyPair(conf.TLS.TLSCertPath, conf.TLS.TLSKeyPath)
	if err != nil {
		log.Println(err)
		return
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", conf.Address, config)
	if err != nil {
		log.Println(err)
		return
	}

	server.waitStop.Add(1)
	go server.listenForRequests(ln)

	server.waitStop.Add(1)
	go server.updatePolicies()
}

func (server *ConiksServer) EpochUpdate() {
	defer server.waitStop.Done()
	for {
		select {
		case <-server.stop:
			return
		case <-server.epochTimer.C:
			server.Lock()
			server.directory.Update(server.policies)
			// clear issued temporary bindings
			for key := range server.tbs {
				delete(server.tbs, key)
			}
			server.Unlock()
			server.policiesMutex.Lock()
			server.epochTimer.Reset(time.Duration(server.policies.EpDeadline()) * time.Second)
			server.policiesMutex.Unlock()
		}
	}
}

func (server *ConiksServer) Shutdown() {
	close(server.stop)
	server.waitStop.Wait()
}

func (server *ConiksServer) updatePolicies() {
	defer server.waitStop.Done()
	for {
		select {
		case <-server.stop:
			return
		case <-server.reloadChan:
			p, err := readPolicies(server.policiesFilePath)
			if err != nil {
				log.Println("open config: ", err)
			}
			server.policiesMutex.Lock()
			server.policies = merkletree.NewPolicies(p.EpochDeadline, &p.VRFKey)
			server.policiesMutex.Unlock()
			log.Println("Policies reloaded!")
		}
	}
}
