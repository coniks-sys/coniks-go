# CONIKS Server implementation in Golang

## Usage
```
⇒  go install github.com/coniks-sys/coniks-go/keyserver/coniksserver
⇒  coniksserver -h
 _______  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|

Usage:
  coniksserver [command]

Available Commands:
  init        Create a configuration file and generate all keys
  run         Run a CONIKS server instance

Flags:
  -h, --help   help for coniksserver

Use "coniksserver [command] --help" for more information about a command.
```

Run the server
```
⇒  mkdir coniks; cd coniks
⇒  coniksserver init -c # create all files including a self-signed tls cert
⇒  coniksserver run -p  # run & write down the process ID into coniks.pid
```

You can reload the server's policies while it's running by editing the `config.toml` file
and possibly replace `vrf.priv` with a new key, then run
```
⇒  kill -USR2 `cat coniks.pid`
```

## Disclaimer
Please keep in mind that this CONIKS server implementation is under active
development. The repository may contain experimental features that aren't
fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).
