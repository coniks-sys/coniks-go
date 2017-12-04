// Executable CONIKS key server. See README for
// usage instructions.
package main

import (
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/cli/coniksserver/internal/cmd"
)

func main() {
	cli.Execute(cmd.RootCmd)
}
