package cmd

import (
	"fmt"
	"net"
	"os"

	"encoding/json"

	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	"github.com/coniks-sys/coniks-go/protocol"
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
		name := cmd.Flag("name").Value.String()
		key := cmd.Flag("key").Value.String()
		if len(name) == 0 || len(key) == 0 {
			cmd.Usage()
			return
		}
		msg, err := createRegistrationMsg(name, key)
		if err != nil {
			fmt.Println("Couldn't marshal registration request!")
			os.Exit(1)
		}

		addr, err := net.ResolveUnixAddr("unix", cmd.Flag("socket").Value.String())
		if err != nil {
			fmt.Println("Invalid socket address: " + err.Error())
			os.Exit(1)
		}
		res, err := testutil.NewUnixClient(msg, addr)
		if err != nil {
			fmt.Println("Error while receiving response: " + err.Error())
		}
		var response testutil.ExpectingDirProofResponse
		err = json.Unmarshal(res, &response)
		if err != nil {
			fmt.Println("Couldn't un-marshal response!")
			os.Exit(1)
		}
		switch response.Error {
		case protocol.Success:
			// TODO Do some validation!?
			fmt.Println("Successfully registerd name.")
		case protocol.ErrorNameExisted:
			fmt.Println("Name is already registered.")
		case protocol.ErrorDirectory:
			// TODO From a usability perspective: how would a real
			// client deal with such an error? Retry?
			fmt.Println("Internal server error.")
		case protocol.ErrorMalformedClientMessage:
			fmt.Println("Server reported an invalid client request!")
		}
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringP("name", "n", "", "Username you want to register with the CONIKS server.")

	// TODO if this test-client should be able to handle real key-material,
	// it should be possible to pass a file containing the key instead.
	registerCmd.Flags().StringP("key", "k", "", "Key-material you want to bind to the user name.")

	// TODO use the same directory as the server by default:
	registerCmd.Flags().StringP("socket", "s", "/tmp/coniks.sock", "The socket on which the client can directly connect to the key-server.")
}

func createRegistrationMsg(name, key string) ([]byte, error) {
	return json.Marshal(&protocol.Request{
		Type: protocol.RegistrationType,
		Request: &protocol.RegistrationRequest{
			Username: name + "@testService",
			Key:      []byte(key),
		},
	})
}
