package cmd

import (
	"os"
	"os/signal"

	"github.com/coniks-sys/coniks-go/application/bots"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = cli.NewRunCommand("CONIKS bot", run)

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "botconfig.toml", "Path to bot configuration file")
}

func run(cmd *cobra.Command, args []string) {
	confPath := cmd.Flag("config").Value.String()
	bot, err := bots.NewTwitterBot(confPath)
	if err != nil {
		panic(err)
	}

	bot.Run()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	bot.Stop()
}
