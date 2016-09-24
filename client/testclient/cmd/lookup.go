package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var lookupCmd = &cobra.Command{
	Use:   "lockup",
	Short: "Lookup a name.",
	Long:  `Lookup the key of some known contact.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO: not implmented yet.")
	},
}

func init() {
	RootCmd.AddCommand(lookupCmd)
	lookupCmd.Flags().StringP("name", "n", "", "User-name of the contact you want to do the look-up for.")
}
