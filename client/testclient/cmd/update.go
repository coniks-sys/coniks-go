package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// TODO figure out if this needs to be a separate command or we can simply re-use
// the registerCmd. Both requests should be identical?
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a name-to-key binding.",
	Long:  `Update a already registered name-to-key binding on the CONIKS-server by first contacting the twitter-bot.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: not implmented yet.")
	},
}

func init() {
	RootCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringP("name", "n", "", "Registered username for which the key should be updated on the CONIKS server.")
	updateCmd.Flags().StringP("key", "k", "", "The new key-material you want to bind to the name.")
}
