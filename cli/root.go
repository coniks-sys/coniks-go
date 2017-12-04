package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// A rootCommand is used to create a CONIKS executable's
// root command that executes all subcommands.
type rootCommand struct {
	use   string
	short string
	long  string
}

var _ cobraCommand = (*rootCommand)(nil)

// NewRootCommand constructs a new RootCommand for the given
// exectuable's use, short and long descriptions.
func NewRootCommand(use, short, long string) *cobra.Command {
	rootCmd := &rootCommand{
		use:   use,
		short: short,
		long:  long,
	}
	return rootCmd.Build()
}

// Build constructs the cobra.Command according to the
// RootCommand's settings.
func (rootCmd *rootCommand) Build() *cobra.Command {
	cmd := cobra.Command{
		Use:   rootCmd.use,
		Short: rootCmd.short,
		Long:  rootCmd.long,
	}
	return &cmd
}

// ExecuteRoot adds all subcommands (i.e. "init" and "run") to the RootCmd
// and sets their flags appropriately.
func ExecuteRoot(rootCmd *cobra.Command) {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
