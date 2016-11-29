package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/crypto/sign"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
)

const configMissingUsage = `
Couldn't load client's config-file.

To create a valid config, first, run
  coniksserver init
if you haven't done this already. This will create a valid server configuration
and also store the server's public keys (by default in sign.pub and vrf.pub).
Then, run
  testclient init
this creates a toml file which references these public-keys.

The client looks for a file called 'config.toml' in its current working directory.
If you prefer the config-file to be named or stored somewhere different you can
specify where to look for the config with the --config flag. For example:
 testclient [cmd] --config /etc/coniks/clientconfig.toml
`

func loadConfigOrExit(cmd *cobra.Command) *client.Config {
	config := cmd.Flag("config").Value.String()
	conf, err := client.LoadConfig(config)
	if err != nil {
		fmt.Println(err)
		fmt.Print(configMissingUsage)
		os.Exit(-1)
	}
	return conf
}

func storeState(cc *protocol.ConsistencyChecks, filename string) error {
	buff, err := json.Marshal(cc)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, buff, 0644)
}

func loadState(filename string, signKey sign.PublicKey) *protocol.ConsistencyChecks {
	var cc protocol.ConsistencyChecks
	buff, err := ioutil.ReadFile(filename)
	if err != nil {
		return protocol.NewCC(nil, true, signKey)
	}
	if err := json.Unmarshal(buff, &cc); err != nil {
		return protocol.NewCC(nil, true, signKey)
	}
	restoredCC := protocol.NewCC(nil, true, signKey)
	restoredCC.RestoreState(cc.Bindings, cc.TBs)
	return restoredCC
}
