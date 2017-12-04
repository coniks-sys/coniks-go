package cli

import (
	"github.com/spf13/cobra"
)

// A runCommand is used to create a CONIKS executable's
// main functionality.
type runCommand struct {
	appName string
	runFunc func(cmd *cobra.Command, args []string)
}

var _ cobraCommand = (*runCommand)(nil)

// NewRunCommand constructs a new RunCommand for the given
// exectuable's appName and the runFunc implementing
// the main functionality run command.
func NewRunCommand(appName string, runFunc func(cmd *cobra.Command, args []string)) *cobra.Command {
	runCmd := &runCommand{
		appName: appName,
		runFunc: runFunc,
	}
	return runCmd.Build()
}

// Build constructs the cobra.Command according to the
// RunCommand's settings.
func (runCmd *runCommand) Build() *cobra.Command {
	cmd := cobra.Command{
		Use:   "run",
		Short: "Run a " + runCmd.appName + " instance.",
		Long: `Run a ` + runCmd.appName + ` instance.

This will look for config files with default names
in the current directory if not specified differently.
	`,
		Run: runCmd.runFunc,
	}
	return &cmd
}
