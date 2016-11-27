# CLI CONIKS Client implementation in Golang

## Usage
```
⇒  go install github.com/coniks-sys/coniks-go/client/coniksclient
⇒  coniksclient -h
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|

Usage:
  coniksclient [command]

Available Commands:
  init        Creates a config file for the client.
  lookup      Lookup a name.
  register    Register a name-to-key binding.

Use "coniksclient [command] --help" for more information about a command.
```

## Disclaimer
__Do not use your real public key or private key with this test client.__

Please keep in mind that this CONIKS client implementation is under active development. The repository may contain experimental features that aren't fully tested.
