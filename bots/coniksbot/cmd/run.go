package cmd

import (
	"os"
	"os/signal"
	"path"

	"github.com/coniks-sys/coniks-go/bots"
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
		dir := cmd.Flag("dir").Value.String()
		config := cmd.Flag("config").Value.String()

		confPath := path.Join(dir, config)
		run(confPath)
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("dir", "d", ".", "Location of bot working directory")
	runCmd.Flags().StringP("config", "c", "botconfig.toml", "Configuration filename")
}

func run(confPath string) {
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
