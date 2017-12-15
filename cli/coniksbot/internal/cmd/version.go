package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

var versionCmd = cli.NewVersionCommand("coniksbot")

func init() {
	RootCmd.AddCommand(versionCmd)
}
