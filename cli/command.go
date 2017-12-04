package cli

import (
	"github.com/spf13/cobra"
)

// cobraCommand is used to implement any type of cobra command
// for any of the CONIKS command-line tools and executables.
type cobraCommand interface {
	Build() *cobra.Command
}
