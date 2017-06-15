package cmd

import (
	"bytes"
	"log"
	"path"
	"strconv"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/coniksserver"
	"github.com/coniks-sys/coniks-go/coniksserver/testutil"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
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
	addrs := []*coniksserver.Address{
		&coniksserver.Address{
			Address:           "unix:///tmp/coniks.sock",
			AllowRegistration: true,
		},
		&coniksserver.Address{
			Address:     "tcp://0.0.0.0:3000",
			TLSCertPath: "server.pem",
			TLSKeyPath:  "server.key",
		},
	}
	var conf = coniksserver.ServerConfig{
		LoadedHistoryLength: 1000000,
		Addresses:           addrs,
		Policies: &coniksserver.ServerPolicies{
			EpochDeadline: 60,
			VRFKeyPath:    "vrf.priv",
			SignKeyPath:   "sign.priv",
		},
		Logger: &utils.LoggerConfig{
			EnableStacktrace: true,
			Environment:      "development",
			Path:             "coniksserver.log",
		},
	}

	var confBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	err := e.Encode(conf)
	if err != nil {
		log.Println(err)
		return
	}
	utils.WriteFile(file, confBuf.Bytes(), 0644)
}

func mkSigningKey(dir string) {
	sk, err := sign.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	pk, _ := sk.Public()
	if err := utils.WriteFile(path.Join(dir, "sign.priv"), sk, 0600); err != nil {
		log.Println(err)
		return
	}
	if err := utils.WriteFile(path.Join(dir, "sign.pub"), pk, 0600); err != nil {
		log.Println(err)
		return
	}
}

func mkVrfKey(dir string) {
	sk, err := vrf.GenerateKey(nil)
	if err != nil {
		log.Print(err)
		return
	}
	pk, _ := sk.Public()
	if err := utils.WriteFile(path.Join(dir, "vrf.priv"), sk, 0600); err != nil {
		log.Println(err)
		return
	}
	if err := utils.WriteFile(path.Join(dir, "vrf.pub"), pk, 0600); err != nil {
		log.Println(err)
		return
	}
}
