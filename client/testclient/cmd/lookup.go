package cmd

import (
	"encoding/json"
	"fmt"
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
		conf := loadConfigOrExit(cmd)
		name := cmd.Flag("name").Value.String()
		if len(name) == 0 {
			cmd.Usage()
			return
		}
		req, err := createLookupRequest(name)
		if err != nil {
			fmt.Println("Couldn't create request!")
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
		case p.ReqSuccess:
			// FIXME reuse/load the cc from the registration instead:
			cc := p.NewCC(nil, true, conf.SigningPubKey)
			ap := response.DirectoryResponse.(*p.DirectoryProof).AP
			// FIXME same comment as in register.go
			err := cc.HandleResponse(p.KeyLookupType, response, name, nil)
			if err != p.CheckPassed {
				fmt.Printf("Couldn't validate response: %s\n", err)
			} else {
				fmt.Println("Sucess! Key bound to name is: [" + string(ap.Leaf.Value) + "]")
			}
		case p.ErrMalformedClientMessage:
			fmt.Println("Server reported malformed client message.")
		case p.ReqNameNotFound:
			// TODO refactor common code (see p.Success case above):
			cc := p.NewCC(nil, true, conf.SigningPubKey)
			ap := response.DirectoryResponse.(*p.DirectoryProof).AP
			key := ap.Leaf.Value
			// FIXME same comment as in register.go
			err := cc.HandleResponse(p.KeyLookupType, response, name, key)
			if err != p.CheckPassed {
				fmt.Printf("Couldn't validate response: %s\n", err)
			}
			fmt.Println("Name isn't registered.")
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
