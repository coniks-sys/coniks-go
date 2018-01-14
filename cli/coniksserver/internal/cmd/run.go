package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"

	"github.com/coniks-sys/coniks-go/application/server"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = cli.NewRunCommand("CONIKS server",
	`Run a CONIKS server instance.

This will look for config files with default names
in the current directory if not specified differently.
	`, run)

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "config.toml", "Path to server configuration file")
	runCmd.Flags().BoolP("pid", "p", false, "Write down the process id to coniks.pid in the current working directory")
}

func run(cmd *cobra.Command, args []string) {
	confPath := cmd.Flag("config").Value.String()
	pid, _ := strconv.ParseBool(cmd.Flag("pid").Value.String())
	// ignore the error here since it is handled by the flag parser.
	if pid {
		writePID()
	}

	conf := &server.Config{}
	if err := conf.Load(confPath, "toml"); err != nil {
		log.Fatal(err)
	}
	serv := server.NewConiksServer(conf)

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
