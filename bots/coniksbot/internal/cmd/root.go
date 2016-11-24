// Package cmd provides the CLI commands for a CONIKS
// account verification bot for Twitter accounts.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base "coniksbot" command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "coniksbot",
	Short: "CONIKS bot for third-party account verification",
	Long:  `CONIKS bot for third-party account verification`,
}

// Execute adds all subcommands (i.e. "init" and "run") to the RootCmd
// and sets their flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
