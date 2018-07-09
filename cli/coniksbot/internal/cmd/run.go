package cmd

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/coniks-sys/coniks-go/application/bots"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = cli.NewRunCommand("CONIKS bot",
	`Run a CONIKS bot instance.

This will look for config files with default names
in the current directory if not specified differently.
	`, run)

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "botconfig.toml", "Path to bot configuration file")
}

func run(cmd *cobra.Command, args []string) {
	confPath := cmd.Flag("config").Value.String()
	conf := &bots.TwitterConfig{}
	if err := conf.Load(confPath, "toml"); err != nil {
		fmt.Println(err)
		fmt.Print("Couldn't load the bot's config-file.")
		os.Exit(-1)
	}

	bot, err := bots.NewTwitterBot(conf)
	if err != nil {
		panic(err)
	}

	bot.Run()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	bot.Stop()
}
