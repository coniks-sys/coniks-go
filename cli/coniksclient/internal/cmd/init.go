package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/coniks-sys/coniks-go/application/client"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/spf13/cobra"
)

var initCmd = cli.NewInitCommand("CONIKS test client", mkConfigOrExit)

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".",
		"Location of directory for storing generated files")
}

func mkConfigOrExit(cmd *cobra.Command, args []string) {
	dir := cmd.Flag("dir").Value.String()
	file := path.Join(dir, "config.toml")
	conf := client.NewConfig(file, "toml", "../coniksserver/sign.pub",
		"../../keyserver/coniksserver/init.str",
		"tcp://127.0.0.1:3000", "tcp://127.0.0.1:3000")

	if err := conf.Save(); err != nil {
		fmt.Println("Couldn't save config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
