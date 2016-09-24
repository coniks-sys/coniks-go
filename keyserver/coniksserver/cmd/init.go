package cmd

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/keyserver"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	"github.com/coniks-sys/coniks-go/utils"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a configuration file and generate all keys",
	Long:  `Create a configuration file and generate all keys for signing and VRF`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := cmd.Flag("dir").Value.String()
		mkConfig(dir)
		mkSigningKey(dir)
		mkVrfKey(dir)

		cert, err := strconv.ParseBool(cmd.Flag("cert").Value.String())
		if err == nil && cert {
			testutil.CreateTLSCert(dir)
		}
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".", "Location of directory for storing generated files")
	initCmd.Flags().BoolP("cert", "c", false, "Generate self-signed ssl keys/cert with sane defaults")
}

func mkConfig(dir string) {
	file := path.Join(dir, "config.toml")
	addrs := []*keyserver.Address{
		&keyserver.Address{
			Address:           "unix:///tmp/coniks.sock",
			AllowRegistration: true,
		},
		&keyserver.Address{
			Address:     "tcp://0.0.0.0:3000",
			TLSCertPath: "server.pem",
			TLSKeyPath:  "server.key",
		},
	}
	var conf = keyserver.ServerConfig{
		DatabasePath:        "coniks.db",
		LoadedHistoryLength: 1000000,
		Addresses:           addrs,
		Policies: &keyserver.ServerPolicies{
			EpochDeadline: 60,
			VRFKeyPath:    "vrf.priv",
			SignKeyPath:   "sign.priv",
		},
	}

	var confBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	err := e.Encode(conf)
	if err != nil {
		log.Println(err)
		return
	}
	utils.WriteFile(file, confBuf)
}

func mkSigningKey(dir string) {
	sk, err := sign.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	// TODO the code below should be refactored to a single function
	// (vrf and sign are almost identical here)
	file := path.Join(dir, "sign.priv")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	if err := ioutil.WriteFile(file, sk[:], 0600); err != nil {
		log.Print(err)
		return
	}
	// public-key needed for test client:
	file = path.Join(dir, "sign.pub")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	signKeyPub, _ := sk.Public()
	if err := ioutil.WriteFile(file, signKeyPub, 0600); err != nil {
		log.Print(err)
		return
	}
}

func mkVrfKey(dir string) {
	sk, err := vrf.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	file := path.Join(dir, "vrf.priv")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	if err := ioutil.WriteFile(file, sk[:], 0600); err != nil {
		log.Print(err)
		return
	}
	// public-key needed for test client:
	file = path.Join(dir, "vrf.pub")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	vrfKeyPub, _ := sk.Public()
	if err := ioutil.WriteFile(file, vrfKeyPub, 0600); err != nil {
		log.Print(err)
		return
	}
}
