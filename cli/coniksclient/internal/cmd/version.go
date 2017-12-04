package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

var versionCmd = cli.NewVersionCommand("coniksclient")

func init() {
	RootCmd.AddCommand(versionCmd)
}
