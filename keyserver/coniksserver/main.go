package main

import (
	"bytes"
	"flag"
	"os"
	"os/signal"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/keyserver"
	"github.com/coniks-sys/coniks-go/utils"
)

const ConfigFile = "config.toml"
const PoliciesFile = "policies.toml"

func main() {
	genConfigPtr := flag.Bool("genconfig", false, "Generate server config")
	configPathPtr := flag.String("config", "config.toml", "path to config file")
	flag.Parse()

	if *genConfigPtr {
		mkConfig()
		return
	}

	// set up a CONIKS server from config file
	conf := keyserver.LoadServerConfig(*configPathPtr)
	serv := keyserver.NewConiksServer(conf)

	// run the server until receiving an interrupt signal
	serv.RunWithConfig(conf)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	serv.Shutdown()
}

func mkConfig() {
	var conf = keyserver.ServerConfig{
		SigningKeyPath:       "ed25519.secret",
		DatabasePath:         "coniks.db",
		RegistrationAddress:  "127.0.0.1:3001",
		Address:              "0.0.0.0:3000",
		PoliciesPath:         "policies.toml",
		LoadedHistoryLength:  1000000,
		RegistrationCapacity: 100000,
	}
	conf.TLS.TLSCertPath = "server.pem"
	conf.TLS.TLSKeyPath = "server.key"

	var policies = keyserver.ServerPolicies{
		EpochDeadline: 60,
		VRFKeyPath:    "vrf.secret",
	}

	var confBuf bytes.Buffer
	var policiesBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	err := e.Encode(conf)
	if err != nil {
		panic(err)
	}
	util.WriteFile(ConfigFile, confBuf)

	e = toml.NewEncoder(&policiesBuf)
	err = e.Encode(policies)
	if err != nil {
		panic(err)
	}
	util.WriteFile(PoliciesFile, policiesBuf)
}
