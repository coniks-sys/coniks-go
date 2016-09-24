# CLI CONIKS Client implementation in Golang
__Do not use your real public key or private key with this test client.__

## Usage

##### Install the test client
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

##### Create a config file for the client
```
⇒  coniksclient init
```
You may have to modify the config file accordingly the location of the server's public keys and the server's addresses.

##### Register a new name-to-public key mapping with the CONIKS server
```
⇒  coniksclient register -n alice -k alice_fake_public_key
# The client should display something like this if the request is successful
Succesfully registered name: alice
```

##### Look up a public key
```
⇒  coniksclient lookup -n alice
# The client should display something like this if the request is successful
Success! Key bound to name is: [alice_fake_public_key]
```

## Disclaimer
Please keep in mind that this CONIKS client implementation is under active development. The repository may contain experimental features that aren't fully tested.
