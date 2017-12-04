package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

// RootCmd represents the base "testclient" command when called without any
// subcommands (register, lookup, ...).
var RootCmd = cli.NewRootCommand("coniksclient",
	"CONIKS test client reference implementation in Go",
	`
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|
`)
