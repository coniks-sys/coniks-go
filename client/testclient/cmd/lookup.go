package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
)

var lookupCmd = &cobra.Command{
	Use:   "lookup",
	Short: "Lookup a name.",
	Long:  `Lookup the key of some known contact.`,
	Run: func(cmd *cobra.Command, args []string) {
		config := cmd.Flag("config").Value.String()
		conf, err := client.LoadConfig(config)
		if err != nil {
			log.Fatal(err)
		}

		name := cmd.Flag("name").Value.String()
		if len(name) == 0 {
			cmd.Usage()
			return
		}
		req, err := createLookupRequest(name)
		if err != nil {
			fmt.Println("Couldn'r create request!")
			os.Exit(-1)
		}
		resp, err := testutil.NewTCPClient(req)
		if err != nil {
			fmt.Println("Error while retrieving repsonse: " + err.Error())
			os.Exit(-1)
		}
		response, errCode := client.UnmarshalResponse(p.KeyLookupType,
			resp)
		switch errCode {
		case p.Success:
			res, ok := response.(*p.DirectoryProof)
			if !ok {
				fmt.Println("Got unexpected response from server!")
				os.Exit(-1)
			}
			c := res.Verify(name, []byte(res.AP.Leaf.Value), 0, nil,
				conf.SigningPubKey)
			// verify auth. path:
			if c != p.Passed || !res.AP.Verify(res.STR.TreeHash) {
				fmt.Println("Response message didn't pass verification (invalid auth. path).")
			}
			if res.TB != nil {
				tbb := res.TB.Serialize(res.STR.Signature)
				if !conf.SigningPubKey.Verify(tbb, res.TB.Signature) {
					fmt.Println("Got invalid TB!")
				}
				fmt.Println("Sucess! Got temporary binding (check again after next epoch). Key is: " +
					string(res.TB.Value) + " will be inserted at index:\n" + hex.Dump(res.TB.Index))
			}
			fmt.Println("Sucess! Key for name is: " + string(res.AP.Leaf.Value))
			fmt.Println("Index:\n" + hex.Dump(res.AP.Leaf.Index))

		case p.ErrorMalformedClientMessage:
			fmt.Println("Server reported malformed client message.")
		case p.ErrorNameNotFound:
			fmt.Println("Name isn't registered.")
			// TODO verify auth. path / proof of absence?!
		default:
			fmt.Println(errCode)
			os.Exit(-1)
		}

	},
}

func init() {
	RootCmd.AddCommand(lookupCmd)
	lookupCmd.Flags().StringP("name", "n", "",
		"User-name of the contact you want to do the look-up for.")
	lookupCmd.Flags().StringP("config", "c", "config.toml",
		"Config file for the client (contains the server's initial public key etc.)")
}

func createLookupRequest(name string) ([]byte, error) {
	return json.Marshal(&p.Request{
		Type: p.KeyLookupType,
		Request: &p.KeyLookupRequest{
			Username: name,
		},
	})
}
