package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"

	"github.com/coniks-sys/coniks-go/coniksserver"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a CONIKS server instance",
	Long: `Run a CONIKS server instance

This will look for config files with default names (config.toml)
in the current directory if not specified differently.
	`,
	Run: func(cmd *cobra.Command, args []string) {
		config := cmd.Flag("config").Value.String()
		pid, _ := strconv.ParseBool(cmd.Flag("pid").Value.String())
		// ignore the error here since it is handled by the flag parser.
		if pid {
			writePID()
		}
		run(config)
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "config.toml", "Path to server configuration file")
	runCmd.Flags().BoolP("pid", "p", false, "Write down the process id to coniks.pid in the current working directory")
}

func run(confPath string) {
	conf, err := coniksserver.LoadServerConfig(confPath)
	if err != nil {
		log.Fatal(err)
	}
	serv := coniksserver.NewConiksServer(conf)

	// run the server until receiving an interrupt signal
	serv.Run(conf.Addresses)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	serv.Shutdown()
}

func writePID() {
	pidf, err := os.OpenFile(path.Join(".", "coniks.pid"), os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Printf("Cannot create coniks.pid: %v", err)
		return
	}
	if _, err := fmt.Fprint(pidf, os.Getpid()); err != nil {
		log.Printf("Cannot write to pid file: %v", err)
	}
}
