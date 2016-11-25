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
		response := client.UnmarshalResponse(p.KeyLookupType, resp)
		// FIXME reuse/load the cc from the registration instead
		// FIXME same comment as in register.go
		cc := p.NewCC(nil, true, conf.SigningPubKey)
		err = cc.HandleResponse(p.KeyLookupType, response, name, nil)
		switch err {
		case p.CheckPassed:
			switch response.Error {
			case p.ReqSuccess:
				// TODO: implement response.GetKey()
				fmt.Println("Sucess! Key bound to name is: [" + "" + "]")
			case p.ReqNameNotFound:
				fmt.Println("Name isn't registered.")
			}
		default:
			fmt.Println("Error: " + err.Error())
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
