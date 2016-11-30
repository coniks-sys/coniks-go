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

### Configure the server

- Generate the configuration file:
```
⇒  mkdir coniks; cd coniks
⇒  coniksserver init -c # create all files including a self-signed tls keys/cert
```
- By default, the configuration file has two `addresses` entries: the first
is for the registration proxy, the second is the server's public address
for "read-only" requests (lookups, monitoring etc).
- Edit the configuration file as needed:
    - Replace the `epoch_deadline` with the desired duration in seconds.
    - If using a CONIKS registration proxy, replace the registration proxy `address`. Otherwise, remove the registration proxy `addresses` entry, and add `allow_registration = true` field to the public `addresses` entry.
    - In either case, replace the public `address` with the server's public CONIKS address.
- Test setup (no registration proxy) config file example:
```
[policies]
...
[[addresses]]
    address = "tcp://public.server.address:port"
    allow_registration = true
    cert = "server.pem"
    key = "server.key"
```

### Run the server
```
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
