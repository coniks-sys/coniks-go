// Package cmd provides the CLI commands for a CONIKS
// account verification bot for Twitter accounts.
package cmd

import (
	"github.com/coniks-sys/coniks-go/cli"
)

// RootCmd represents the base "coniksbot" command when called without any subcommands.
var RootCmd = cli.NewRootCommand("coniksbot",
	"CONIKS bot for third-party account verification",
	`CONIKS bot for third-party account verification`)
