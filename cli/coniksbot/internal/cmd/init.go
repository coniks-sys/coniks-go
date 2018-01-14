package cmd

import (
	"log"
	"path"

	"github.com/coniks-sys/coniks-go/application/bots"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = cli.NewInitCommand("CONIKS bot", mkBotConfig)

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".", "Location of directory for storing generated files")
}

func mkBotConfig(cmd *cobra.Command, args []string) {
	dir := cmd.Flag("dir").Value.String()
	file := path.Join(dir, "botconfig.toml")

	oauth := bots.TwitterOAuth{
		ConsumerKey:    "secret",
		ConsumerSecret: "secret",
		AccessToken:    "secret",
		AccessSecret:   "secret",
	}

	conf := bots.NewTwitterConfig(file, "toml", "/tmp/coniks.sock", "ConiksTorMess",
		oauth)
	if err := conf.Save(); err != nil {
		log.Print(err)
	}
}
