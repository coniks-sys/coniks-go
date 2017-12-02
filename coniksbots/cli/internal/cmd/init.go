package cmd

import (
	"log"
	"path"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/application/bots"
	"github.com/spf13/cobra"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a configuration file for CONIKS bot",
	Long:  `Create a configuration file for CONIKS bot`,
	Run: func(cmd *cobra.Command, args []string) {
		dir := cmd.Flag("dir").Value.String()
		mkBotConfig(dir)
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
	initCmd.Flags().StringP("dir", "d", ".", "Location of directory for storing generated files")
}

func mkBotConfig(dir string) {
	file := path.Join(dir, "botconfig.toml")

	oauth := bots.TwitterOAuth{
		ConsumerKey:    "secret",
		ConsumerSecret: "secret",
		AccessToken:    "secret",
		AccessSecret:   "secret",
	}

	conf := bots.NewTwitterConfig("/tmp/coniks.sock", "ConiksTorMess",
		oauth)
	if err := application.SaveConfig(file, conf); err != nil {
		log.Print(err)
	}
}
