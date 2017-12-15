// Executable CONIKS registration proxy for Twitter usernames. See README for
// usage instructions.
package main

import (
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/cli/coniksbot/internal/cmd"
)

func main() {
	cli.Execute(cmd.RootCmd)
}
