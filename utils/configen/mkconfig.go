package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/keyserver"
)

const ConfigFile = "config.toml"
const PoliciesFile = "policies.toml"

func main() {

	var conf = keyserver.ServerConfig{
		SigningKeyPath:       "ed25519.secret",
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
	writeFile(ConfigFile, confBuf)

	e = toml.NewEncoder(&policiesBuf)
	err = e.Encode(policies)
	if err != nil {
		panic(err)
	}
	writeFile(PoliciesFile, policiesBuf)
}

func writeFile(filename string, buf bytes.Buffer) {
	var dir string

	if len(os.Args) < 2 {
		dir = "."
	} else {
		dir = os.Args[1]
	}

	file := path.Join(dir, filename)

	if _, err := os.Stat(file); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists\n", file)
		return
	}

	if err := ioutil.WriteFile(file, []byte(buf.String()), 0644); err != nil {
		log.Printf(err.Error())
		return
	}
}
