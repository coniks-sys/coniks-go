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
	var conf = keyserver.ServerConfig{
		DatabasePath:        "coniks.db",
		LoadedHistoryLength: 1000000,
		TLS: &keyserver.TLSConnection{
			LocalAddress:  "/tmp/coniks.sock",
			PublicAddress: "0.0.0.0:3000",
			TLSCertPath:   "server.pem",
			TLSKeyPath:    "server.key",
		},
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
	util.WriteFile(file, confBuf)
}

func mkSigningKey(dir string) {
	file := path.Join(dir, "sign.priv")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	sk, err := sign.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	if err := ioutil.WriteFile(file, sk[:], 0600); err != nil {
		log.Print(err)
		return
	}
}

func mkVrfKey(dir string) {
	file := path.Join(dir, "vrf.priv")
	if _, err := os.Stat(file); err == nil {
		log.Printf("%s already exists\n", file)
		return
	}
	sk, err := vrf.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	if err := ioutil.WriteFile(file, sk[:], 0600); err != nil {
		log.Print(err)
		return
	}
}
