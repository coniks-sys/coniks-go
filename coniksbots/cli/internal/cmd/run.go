package cmd

import (
	"os"
	"os/signal"

	"github.com/coniks-sys/coniks-go/coniksbots"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a CONIKS bot instance",
	Long: `Run a CONIKS bot instance

This will look for config files with default names (botconfig.toml)
in the current directory if not specified differently.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		config := cmd.Flag("config").Value.String()
		run(config)
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "botconfig.toml", "Path to bot configuration file")
}

func run(confPath string) {
	bot, err := coniksbots.NewTwitterBot(confPath)
	if err != nil {
		panic(err)
	}

	bot.Run()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	bot.Stop()
}
