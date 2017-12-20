package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

// RootCmd represents the base "auditor" command when called without any
// subcommands (register, lookup, ...).
var RootCmd = cli.NewRootCommand("coniksauditor",
	"CONIKS auditor service implementation in Go",
	`
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|
`)
