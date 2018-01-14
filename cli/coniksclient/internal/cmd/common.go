package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/coniks-sys/coniks-go/application/client"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
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
 testclient init --dir /etc/coniks/
`

func loadConfigOrExit(cmd *cobra.Command) *client.Config {
	config := cmd.Flag("config").Value.String()
	conf := &client.Config{}
	if err := conf.Load(config, "toml"); err != nil {
		fmt.Println(err)
		fmt.Print(configMissingUsage)
		os.Exit(-1)
	}
	return conf
}

// append "\r\n" to msg and then write to terminal in raw mode.
func writeLineInRawMode(term *terminal.Terminal, msg string, printTimestamp bool) {
	if printTimestamp {
		term.Write([]byte("<" + time.Now().Format("15:04:05.999999999") + "> "))
	}
	term.Write([]byte(msg + "\r\n"))
}
