package cmd

import (
	"fmt"
	"os"

	"encoding/json"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a name-to-key binding.",
	Long: `Register a new name-to-key binding on the CONIKS-server.

Example call:
  coniksclient register --name Alice@twitter --key fake_test_key`,
	Run: func(cmd *cobra.Command, args []string) {
		conf := loadConfigOrExit(cmd)
		name := cmd.Flag("name").Value.String()
		key := cmd.Flag("key").Value.String()
		if len(name) == 0 || len(key) == 0 {
			cmd.Usage()
			return
		}
		msg, err := createRegistrationMsg(name, key)
		if err != nil {
			fmt.Println("Couldn't marshal registration request!")
			os.Exit(-1)
		}

		addr := cmd.Flag("address").Value.String()
		res, err := testutil.NewUnixClient(msg, addr)
		if err != nil {
			fmt.Println("Error while receiving response: " + err.Error())
		}

		response := client.UnmarshalResponse(p.RegistrationType, res)
		// FIXME: SavedSTR should be read from a persistent storage. Lazy me :(
		cc := p.NewCC(nil, true, conf.SigningPubKey)
		err = cc.HandleResponse(p.RegistrationType, response, name, []byte(key))
		switch err {
		case p.CheckPassed:
			switch response.Error {
			case p.ReqSuccess:
				fmt.Println("Succesfully registered name: " + name)
				// TODO: Save the cc to verify the TB and for later
				// usage (TOFU checks)
			case p.ReqNameExisted:
				// Key-change isn't currently supported; see:
				// https://github.com/coniks-sys/coniks-go/issues/92
				fmt.Println("Name is already registered.")
			}
		default:
			fmt.Println("Error: " + err.Error())
		}
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringP("name", "n", "",
		"Username you want to register with the CONIKS server.")

	// TODO if this test-client should be able to handle real key-material,
	// the client should generate a new key instead. For testing purposes
	// strings are more convenient, though.
	registerCmd.Flags().StringP("key", "k", "",
		"Key-material you want to bind to the user name.")
	registerCmd.Flags().StringP("address", "a", "unix:///tmp/conikstest.sock",
		"The socket on which the client can directly connect to the key-server.")
	registerCmd.Flags().StringP("config", "c", "config.toml",
		"Config file for the client (contains the server's initial public key etc.)")
}

func createRegistrationMsg(name, key string) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.RegistrationType,
		Request: &p.RegistrationRequest{
			Username: name,
			Key:      []byte(key), // TODO maybe generate a new key here
		},
	})
}
