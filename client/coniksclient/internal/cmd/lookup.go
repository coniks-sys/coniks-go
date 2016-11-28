package cmd

import (
	"fmt"
	"net/url"
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
		req, err := client.CreateLookupMsg(name)
		if err != nil {
			fmt.Println("Couldn't create request!")
			os.Exit(-1)
		}

		var res []byte
		u, _ := url.Parse(conf.Address)
		switch u.Scheme {
		case "tcp":
			res, err = testutil.NewTCPClient(req, conf.Address)
			if err != nil {
				fmt.Println("Error while receiving response: " + err.Error())
				return
			}
		case "unix":
			res, err = testutil.NewUnixClient(req, conf.Address)
			if err != nil {
				fmt.Println("Error while receiving response: " + err.Error())
				return
			}
		default:
			fmt.Println("Invalid config!")
			return
		}
		response := client.UnmarshalResponse(p.KeyLookupType, res)
		cc := loadState(conf.KeyStoragePath, conf.SigningPubKey)
		if key, ok := cc.Bindings[name]; ok {
			err = cc.HandleResponse(p.KeyLookupType, response, name, []byte(key))
		} else {
			err = cc.HandleResponse(p.KeyLookupType, response, name, nil)
		}
		switch err {
		case p.CheckPassed:
			switch response.Error {
			case p.ReqSuccess:
				key, err := response.GetKey()
				if err != nil {
					fmt.Println("Cannot get the key from the response, error: " + err.Error())
				} else {
					fmt.Println("Success! Key bound to name is: [" + string(key) + "]")
					if err := storeState(cc, conf.KeyStoragePath); err != nil {
						fmt.Println("Cannot save the key to the file. Error: " + err.Error())
					}
				}
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
