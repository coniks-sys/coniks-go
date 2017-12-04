package cli

import (
	"github.com/spf13/cobra"
)

// An InitCommand is used to create a CONIKS executable's
// configuration.
type initCommand struct {
	appName string
	runFunc func(cmd *cobra.Command, args []string)
}

var _ cobraCommand = (*initCommand)(nil)

// NewInitCommand constructs a new InitCommand for the given
// exectuable's appName and the runFunc implementing
// the initialization command.
func NewInitCommand(appName string, runFunc func(cmd *cobra.Command, args []string)) *cobra.Command {
	initCmd := &initCommand{
		appName: appName,
		runFunc: runFunc,
	}
	return initCmd.Build()
}

// Build constructs the cobra.Command according to the
// InitCommand's settings.
func (initCmd *initCommand) Build() *cobra.Command {
	cmd := cobra.Command{
		Use:   "init",
		Short: "Create a configuration file for " + initCmd.appName + ".",
		Long:  `Create a configuration file for ` + initCmd.appName + `.`,
		Run:   initCmd.runFunc,
	}
	return &cmd
}
