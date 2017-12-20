// Executable CONIKS auditor. See README for
// usage instructions.
package main

import (
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/cli/coniksauditor/internal/cmd"
)

func main() {
	cli.Execute(cmd.RootCmd)
}
