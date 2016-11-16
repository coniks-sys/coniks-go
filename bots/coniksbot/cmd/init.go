package cmd

import (
	"bytes"
	"log"
	"path"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/bots"
	"github.com/coniks-sys/coniks-go/utils"
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
	var conf = bots.TwitterConfig{
		CONIKSAddress: "/tmp/coniks.sock",
		Handle:        "ConiksTorMess",
		TwitterOAuth: bots.TwitterOAuth{
			ConsumerKey:    "secret",
			ConsumerSecret: "secret",
			AccessToken:    "secret",
			AccessSecret:   "secret",
		},
	}

	var confBuf bytes.Buffer

	e := toml.NewEncoder(&confBuf)
	err := e.Encode(conf)
	if err != nil {
		log.Print(err)
		return
	}
	utils.WriteFile(file, confBuf)
}
