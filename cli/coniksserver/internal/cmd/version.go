package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

var versionCmd = cli.NewVersionCommand("coniksserver")

func init() {
	RootCmd.AddCommand(versionCmd)
}
