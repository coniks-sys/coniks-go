package cmd

import (
	"fmt"
	"net"
	"os"

	"encoding/json"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
	"log"
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
		config := cmd.Flag("config").Value.String()
		conf, err := client.LoadConfig(config)
		if err != nil {
			log.Fatal(err)
		}

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

		addr, err := net.ResolveUnixAddr("unix", cmd.Flag("socket").Value.String())
		if err != nil {
			fmt.Println("Invalid socket address: " + err.Error())
			os.Exit(1)
		}
		res, err := testutil.NewUnixClient(msg, addr)
		if err != nil {
			fmt.Println("Error while receiving response: " + err.Error())
		}

		response, errCode := client.UnmarshalResponse(p.RegistrationType,
			res)
		switch errCode {
		case p.Success:
			// TODO Do some validation!?
			res, ok := response.(*p.DirectoryProof)
			if !ok {
				fmt.Println("Got unexpected response from server!")
				os.Exit(-1)
			}
			// TODO why are the implementations for this verification
			// method all empty? (see: protocol/message.go)
			c := res.Verify(name, []byte(key), 0, nil,
				conf.SigningPubKey)
			// verify auth. path:
			if c != p.Passed || !res.AP.Verify(res.STR.TreeHash) {
				fmt.Println("Response message didn't pass verification (invalid auth. path).")
			}
			// verify signature on TB:
			tbb := res.TB.Serialize(res.STR.Signature)
			if !conf.SigningPubKey.Verify(tbb, res.TB.Signature) {
				fmt.Println("Couldn't verify signature of temporary binding.")
			}
			fmt.Println("Succesfully registered name: " + name)
			// TODO Where should the client save seen STRs and the TB?
			// (or should it wait till the next epoch to see if the
			// TB was actually inserted?)
		case p.ErrorNameExisted:
			// FIXME Shouldn't re-registering (or updating) an existing
			// name with new key-material (after at least one epoch
			// has passed) return Success instead of the above error?
			fmt.Println("Name is already registered.")
		case p.ErrorDirectory:
			// From a usability perspective: how would a real
			// client deal with such an error? Retry?
			fmt.Println("Internal server error.")
		case p.ErrorMalformedClientMessage:
			fmt.Println("Server reported an invalid client request!")
		}
	},
}

func init() {
	RootCmd.AddCommand(registerCmd)
	registerCmd.Flags().StringP("name", "n", "",
		"Username you want to register with the CONIKS server.")

	// TODO if this test-client should be able to handle real key-material,
	// it should be possible to pass a file containing the key instead.
	// TODO or this shouldn't be exposed to the user and we just generate
	// some new key
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
			Username: name,        /*+ "@twitter"*/ // a real client would
			Key:      []byte(key), // TODO myabe generate a new key here
		},
	})
}
