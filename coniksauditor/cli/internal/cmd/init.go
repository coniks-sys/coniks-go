package cmd

import (
	"fmt"
	"path"

	"bytes"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/coniksauditor"
	"github.com/coniks-sys/coniks-go/utils"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Creates a config file for the auditor.",
	Long: `Creates a file config.toml in the current working directory with
the following content:

sign_pubkey_path = "../../keyserver/coniksserver/sign.pub"
init_str_path = "../../keyserver/coniksserver/init_str"
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
	var conf = coniksauditor.DirectoryConfig{
		SignPubkeyPath: "../../keyserver/coniksserver/sign.pub",
		InitSTRPath:    "../../keyserver/coniksserver/init_str",
		Address:        "tcp://127.0.0.1:3000",
	}

	var confBuf bytes.Buffer
	enc := toml.NewEncoder(&confBuf)
	if err := enc.Encode(conf); err != nil {
		fmt.Println("Coulnd't encode config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
	if err := utils.WriteFile(file, confBuf.Bytes(), 0644); err != nil {
		fmt.Println("Coulnd't write config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
