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

	conf := client.NewConfig("../coniksserver/sign.pub",
		"tcp://127.0.0.1:3000", "tcp://127.0.0.1:3000")

	if err := conf.Save(file); err != nil {
		fmt.Println("Couldn't save config. Error message: [" +
			err.Error() + "]")
		os.Exit(-1)
	}
}
