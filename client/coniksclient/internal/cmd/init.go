package cmd

import (
	"fmt"

	"bytes"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/utils"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a config file for the client.",
	Long: `Creates a file config.toml int the current working directory with
the following content:

sign_pubkey_path = "../../keyserver/coniksserver/sign.pub"
registration_address = "tcp://127.0.0.1:3000"
address = "tcp://127.0.0.1:3000"

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
		RegAddress:     "tcp://127.0.0.1:3000",
		Address:        "tcp://127.0.0.1:3000",
	}

	var confBuf bytes.Buffer
	enc := toml.NewEncoder(&confBuf)
	if err := enc.Encode(conf); err != nil {
		fmt.Println("Coulnd't encode config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
	if err := utils.WriteFile(path, confBuf.Bytes(), 0644); err != nil {
		fmt.Println("Coulnd't write config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
