package cli

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/internal"
	"github.com/spf13/cobra"
)

// A versionCommand is used to display a CONIKS executable's
// version.
type versionCommand struct {
	appName string
}

var _ cobraCommand = (*versionCommand)(nil)

// NewVersionCommand constructs a new VersionCommand for the given
// exectuable's appName.
func NewVersionCommand(appName string) *cobra.Command {
	versCmd := &versionCommand{
		appName: appName,
	}
	return versCmd.Build()
}

// Build constructs the cobra.Command according to the
// VersionCommand's settings.
func (versCmd *versionCommand) Build() *cobra.Command {
	cmd := cobra.Command{
		Use:   "version",
		Short: "Print the version number of " + versCmd.appName + ".",
		Long:  `Print the version number of ` + versCmd.appName + `.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("All software has versions. This is " + versCmd.appName + "'s:")
			fmt.Println(versCmd.appName + " v" + internal.Version)
		},
	}
	return &cmd
}
