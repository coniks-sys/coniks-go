package cmd

import (
	"fmt"

	"bytes"
	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/client"
	"github.com/spf13/cobra"
	"os"

	"github.com/coniks-sys/coniks-go/utils"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a config file for the client.",
	Long: `Creates a file config.toml int the current working directory with
the following content:

sign_pubkey_path = "../../keyserver/coniksserver/sign.pub"
vrf_pubkey_path = "../../keyserver/coniksserver/vrf.pub"

If the keyserver's public keys are somewhere else, you will have to modify the
config file accordingly.
`,
	Run: func(cmd *cobra.Command, args []string) {
		path := cmd.Flag("path").Value.String()
		mkConfigOrExit(path)
		fmt.Println("Created config file: " + path)
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("path", "p", "config.toml",
		"Create the config file in the given absolute path (including the file's name).")
}

func mkConfigOrExit(path string) {
	var conf = client.Config{
		SignPubkeyPath: "../../keyserver/coniksserver/sign.pub",
		VrfPubkeyPath:  "../../keyserver/coniksserver/vrf.pub",
	}

	var confBuf bytes.Buffer
	enc := toml.NewEncoder(&confBuf)
	err := enc.Encode(conf)
	if err != nil {
		fmt.Println("Coulnd't encode config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
	if err := util.CreateFile(path, confBuf); err != nil {
		fmt.Println("Couldn't create config-file. Error was: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
