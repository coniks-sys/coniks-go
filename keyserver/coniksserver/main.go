package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/coniks-sys/coniks-go/keyserver"
)

func main() {
	configPathPtr := flag.String("config", "config.toml", "path to config file")
	flag.Parse()

	// set up a CONIKS server from config file
	conf := keyserver.LoadServerConfig(*configPathPtr)
	serv := keyserver.New(conf)

	// run the server until receiving an interrupt signal
	serv.RunWithConfig(conf)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	serv.Shutdown()
}
