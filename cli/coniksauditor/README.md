# CONIKS Auditor implementation in Golang
__Do not use your real public key or private key with this test auditor.__

## Usage

**Note:** This auditor CLI currently only implements the CONIKS key
directory-to-auditor protocol (i.e. the auditor only retrieves and verifies
STRs from the server, it does _not_ accept auditing requests from clients).
To test the implementation, the auditor can be run with an interactive REPL.

##### Install the test auditor
```
⇒  go install github.com/coniks-sys/coniks-go/coniksauditor/cli
⇒  coniksauditor -h
________  _______  __    _  ___  ___   _  _______
|       ||       ||  |  | ||   ||   | | ||       |
|       ||   _   ||   |_| ||   ||   |_| ||  _____|
|       ||  | |  ||       ||   ||      _|| |_____
|      _||  |_|  ||  _    ||   ||     |_ |_____  |
|     |_ |       || | |   ||   ||    _  | _____| |
|_______||_______||_|  |__||___||___| |_||_______|

Usage:
  coniksauditor [command]

Available Commands:
  init        Creates a config file for the auditor.
  test        Run the interactive test auditor.

Use "coniksauditor [command] --help" for more information about a command.
```

### Configure the auditor

- Make sure you have at least one running CONIKS directory for your
auditor to track. For information on setting up a CONIKS directory,
see our [CONIKS server setup guide](https://github.com/coniks-sys/coniks-go/blob/master/coniksserver/README.md).

- Generate the configuration file:
```
⇒  mkdir coniks-auditor; cd coniks-auditor
⇒  coniksauditor init
```
- Ensure the auditor has the directory's *test* public signing key.
- Edit the configuration file as needed:
    - Replace the `sign_pubkey_path` with the location of the directory's public signing key.
    - Replace the `init_str_path` with the location of the directory's initial signed tree root.
    - Replace the `address` with the directory's public CONIKS address (for lookups, monitoring etc).
_Note: The auditor is capable of verifying multiple key directories, but
we currently only  configure the test auditor with a single directory for simplcity._

### Run the test auditor

```
⇒  coniksauditor test  # this will open a REPL
```

##### Update the auditor with the latest STR history from the given directory
```
> update [dir]
# The auditor should display something like this if the request is successful
[+] Valid! The auditor is up-to-date on the STR history of [dir]
```

This command updates the auditor's STR log for the directory upon a
successful audit.

##### Retrieve and verify a specific STR history range
```
> getrange [dir] [start] [end]
# The auditor should display something like this if the request is successful
[+] Success! The requested STR history range for [dir] is valid
```

This command only performs an audit on the requested STR history range.
It does not update the auditor's STR log for the directory.

##### Other commands

Use `help` for more information.

Use `exit` to close the REPL and exit the client.

## Disclaimer
Please keep in mind that this CONIKS auditor is under active development.
The repository may contain experimental features that aren't fully tested.
We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).
