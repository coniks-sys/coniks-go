package cmd

import (
	"fmt"

	"github.com/coniks-sys/coniks-go/internal"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of coniksbot.",
	Long:  `Print the version number of coniksbot.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("All software has versions. This is coniksbot's:")
		fmt.Println("coniksbot v" + internal.Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
