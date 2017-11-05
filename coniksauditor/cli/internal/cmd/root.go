package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base "auditor" command when called without any
// subcommands (register, lookup, ...).
var RootCmd = &cobra.Command{
	Use:   "coniksauditor",
	Short: "CONIKS auditor reference implementation in Go",
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

// Execute adds all child commands to the root command sets flags
// appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
