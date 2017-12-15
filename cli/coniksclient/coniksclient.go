// Executable CONIKS test client. See README for
// usage instructions.
package main

import (
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/cli/coniksclient/internal/cmd"
)

func main() {
	cli.Execute(cmd.RootCmd)
}
