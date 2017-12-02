package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/application/client"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a config file for the client.",
	Long: `Creates a file config.toml in the current working directory with
the following content:

sign_pubkey_path = "../../keyserver/coniksserver/sign.pub"
registration_address = "tcp://127.0.0.1:3000"
address = "tcp://127.0.0.1:3000"

If the keyserver's public keys are somewhere else, you will have to modify the
config file accordingly.
`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := cmd.Flag("dir").Value.String()
		mkConfigOrExit(dir)
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".",
		"Location of directory for storing generated files")
}

func mkConfigOrExit(dir string) {
	file := path.Join(dir, "config.toml")

	conf := client.NewConfig("../../keyserver/coniksserver/sign.pub",
		"tcp://127.0.0.1:3000", "tcp://127.0.0.1:3000")

	if err := application.SaveConfig(file, conf); err != nil {
		fmt.Println("Couldn't save config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
