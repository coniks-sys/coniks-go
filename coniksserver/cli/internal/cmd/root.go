// Package cmd implements the CLI commands for a CONIKS key server.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base "coniksserver" command when called without any subcommands.
var RootCmd = &cobra.Command{
	Use:   "coniksserver",
	Short: "CONIKS reference implementation in Go",
	Long: `
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|
`,
}

// Execute adds all subcommands (i.e. "init" and "run") to the RootCmd
// and sets their flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
