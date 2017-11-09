package cmd

import (
	"log"
	"path"
	"strconv"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/application/server"
	"github.com/coniks-sys/coniks-go/application/testutil"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/crypto/vrf"
	"github.com/coniks-sys/coniks-go/utils"
	"github.com/coniks-sys/coniks-go/utils/binutils"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = cli.NewInitCommand("CONIKS key server", initRunFunc)

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".", "Location of directory for storing generated files")
	initCmd.Flags().BoolP("cert", "c", false, "Generate self-signed ssl keys/cert with sane defaults")
}

func initRunFunc(cmd *cobra.Command, args []string) {
	dir := cmd.Flag("dir").Value.String()
	mkConfig(dir)
	mkSigningKey(dir)
	mkVrfKey(dir)

	cert, err := strconv.ParseBool(cmd.Flag("cert").Value.String())
	if err == nil && cert {
		testutil.CreateTLSCert(dir)
	}
}

func mkConfig(dir string) {
	file := path.Join(dir, "config.toml")
	addrs := []*server.Address{
		&server.Address{
			ServerAddress: &application.ServerAddress{
				Address: "unix:///tmp/coniks.sock",
			},
			AllowRegistration: true,
		},
		&server.Address{
			ServerAddress: &application.ServerAddress{
				Address:     "tcp://0.0.0.0:3000",
				TLSCertPath: "server.pem",
				TLSKeyPath:  "server.key",
			},
		},
	}
	logger := &application.LoggerConfig{
		EnableStacktrace: true,
		Environment:      "development",
		Path:             "coniksserver.log",
	}

	policies := &server.Policies{
		EpochDeadline: 60,
		VRFKeyPath:    "vrf.priv",
		SignKeyPath:   "sign.priv",
	}

	conf := server.NewConfig(addrs, logger, 1000000, policies)
	err := application.SaveConfig(file, conf)

	if err != nil {
		log.Println(err)
	}
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
