package cmd

import (
	"fmt"
	"os"

	"encoding/json"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
	//"encoding/hex"
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

		// FIXME allow to use another address than the one defined in testutil package
		//addr, err := net.ResolveUnixAddr("unix", cmd.Flag("socket").Value.String())
		//if err != nil {
		//	fmt.Println("Invalid socket address: " + err.Error())
		//	os.Exit(1)
		//}
		res, err := testutil.NewUnixClient(msg)
		if err != nil {
			fmt.Println("Error while receiving response: " + err.Error())
		}

		// fmt.Println(hex.Dump(res))
		response, errCode := client.UnmarshalResponse(p.RegistrationType,
			res)
		switch errCode {
		case p.ReqSuccess:
			cc := p.NewCC(nil, true, conf.SigningPubKey)
			// FIXME creating a *protocol.Response out of what we got here
			// seems strange: either modify UnmarshalResponse
			// or modify HandleResponse accordingly:
			resp := &p.Response{errCode, response}
			err := cc.HandleResponse(p.RegistrationType, resp,
				name, []byte(key))
			if err != p.CheckPassed {
				fmt.Printf("Couldn't validate response: %s", err)
				return
			}

			fmt.Println("Succesfully registered name: " + name)
			// TODO Save the cc to verify the TB and for later
			// usage (TOFU checks)
		case p.ReqNameExisted:
			// Key-change isn't currently supported; see:
			// https://github.com/coniks-sys/coniks-go/issues/92
			fmt.Println("Name is already registered.")
		case p.ErrDirectory:
			// From a usability perspective: how would a real
			// client deal with such an error? Retry?
			fmt.Println("Internal server error.")
		case p.ErrMalformedClientMessage:
			fmt.Println("Server reported an invalid client request!")
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
	registerCmd.Flags().StringP("socket", "s", "/tmp/coniks.sock",
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
