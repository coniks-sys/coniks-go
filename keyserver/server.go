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
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/storage/kv"
	"github.com/coniks-sys/coniks-go/storage/kv/leveldbkv"
)

type ServerConfig struct {
	SigningKeyPath       string  `toml:"signing_key"`
	DatabasePath         string  `toml:"database"`
	RegistrationAddress  string  `toml:"reg_address"`
	Address              string  `toml:"address"` // address:port
	LoadedHistoryLength  uint64  `toml:"loaded_history_length"`
	RegistrationCapacity uint64  `toml:"registration_capacity"`
	PoliciesPath         string  `toml:"policies"`
	TLS                  TLSInfo `toml:"tls"`
}

type TLSInfo struct {
	TLSCertPath string `toml:"cert"`
	TLSKeyPath  string `toml:"key"`
}

type ConiksServer struct {
	sync.RWMutex
	directory *protocol.ConiksDirectory

	stop     chan struct{}
	waitStop sync.WaitGroup

	db kv.DB

	policies         *ServerPolicies
	policiesFilePath string // should be final
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

func NewConiksServer(conf *ServerConfig) *ConiksServer {
	// load signing key
	skBytes, err := ioutil.ReadFile(conf.SigningKeyPath)
	if err != nil {
		log.Fatalf("Cannot read signing key: %v", err)
		return nil
	}
	if len(skBytes) != sign.PrivateKeySize {
		log.Fatalf("Signing key must be 64 bytes (got %d)", len(skBytes))
		return nil
	}

	sk := make([]byte, sign.PrivateKeySize)
	copy(sk, skBytes[:sign.PrivateKeySize])

	// open db
	kvdb := leveldbkv.OpenDB(conf.DatabasePath)

	// read server policies
	policies, vrfKey, err := readPolicies(conf.PoliciesPath)
	if err != nil {
		log.Fatalf("Cannot read policies config: %v", err)
		return nil
	}

	// create server instance
	server := new(ConiksServer)
	server.stop = make(chan struct{})
	server.db = kvdb
	server.policies = policies
	server.policiesFilePath = conf.PoliciesPath
	server.reloadChan = make(chan os.Signal, 1)
	signal.Notify(server.reloadChan, syscall.SIGUSR2)
	server.epochTimer = time.NewTimer(time.Duration(policies.EpochDeadline) * time.Second)
	server.directory = protocol.InitDirectory(
		policies.EpochDeadline, vrfKey,
		sk, conf.LoadedHistoryLength,
		true, conf.RegistrationCapacity)

	return server
}

func (server *ConiksServer) RunWithConfig(conf *ServerConfig) {
	server.waitStop.Add(1)
	go server.EpochUpdate()

	// server listener
	cer, err := tls.LoadX509KeyPair(conf.TLS.TLSCertPath, conf.TLS.TLSKeyPath)
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	// server public port
	clientLn, err := tls.Listen("tcp", conf.Address, config)
	if err != nil {
		panic(err)
	}

	// server registration port
	botLn, err := tls.Listen("tcp", conf.RegistrationAddress, config)
	if err != nil {
		panic(err)
	}

	server.waitStop.Add(1)
	go server.listenForRequests(clientLn, server.handleClientMessage)

	server.waitStop.Add(1)
	go server.listenForRequests(botLn, server.handleBotMessage)

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
			server.directory.Update()
			server.epochTimer.Reset(time.Duration(server.policies.EpochDeadline) * time.Second)
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
	defer server.waitStop.Done()
	for {
		select {
		case <-server.stop:
			return
		case <-server.reloadChan:
			// read server policies
			policies, vrfKey, err := readPolicies(server.policiesFilePath)
			if err != nil {
				log.Fatalf("Cannot read policies config: %v", err)
				return
			}
			server.Lock()
			server.directory.SetPolicies(policies.EpochDeadline, vrfKey)
			server.policies = policies
			server.Unlock()
			log.Println("Policies reloaded!")
		}
	}
}
