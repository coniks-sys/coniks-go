// Package cmd implements the CLI commands for a CONIKS key server.
package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

// RootCmd represents the base "coniksserver" command when called without any subcommands.
var RootCmd = cli.NewRootCommand("coniksserver",
	"CONIKS server reference implementation in Go",
	`
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|
`)
