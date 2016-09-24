package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a name-to-key binding.",
	Long: `Register a new name-to-key binding on the CONIKS-server.
Note that, for the registration to work, the test-client needs to be running on the same machine as the key-server.
A real client would first register an app here: https://apps.twitter.com (the UI should make this possible without actually leaving the client application). Then, the client would use the oauth1 API (find the tokens on the [Keys and Access Tokens] tab of the aforementioned page) and contact the (twitter-)bot for a registration request. The twitter bit is also accessible from outside.
For more information consult: https://godoc.org/github.com/coniks-sys/coniks-go/bots

Example call:
  coniksclient register -name Alice@twitter -key fake_test_key`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(cmd.Flag("name").Value.String()) == 0 ||
			len(cmd.Flag("key").Value.String()) == 0 {
			cmd.Usage()
			return
		}
		fmt.Println(cmd.Flag("socket").Value.String())
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringP("name", "n", "", "Username you want to register with the CONIKS server.")
	// TODO if this test-client should be able to handle real key-material,
	// it should be possible to pass a file containing the key instead.
	registerCmd.Flags().StringP("key", "k", "", "Key-material you want to bind to the user name.")
	registerCmd.Flags().StringP("socket", "s", "/tmp/coniks.sock", "The socket on which the client connects to ")
}
