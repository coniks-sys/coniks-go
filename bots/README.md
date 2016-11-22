# CONIKS Registration Bot for Twitter account verification in Golang

## Usage
```
⇒  go install github.com/coniks-sys/coniks-go/bots/coniksbot
⇒  coniksbot -h

Usage:
  coniksbot [command]

Available Commands:
  init        Create a configuration file
  run         Run a CONIKS bot instance

Flags:
  -h, --help          help for coniksbot

Use "coniksbot [command] --help" for more information about a command.
```

### Configure the bot

- Generate the configuration file:
```
⇒  mkdir coniksbot; cd coniksbot
⇒  coniksbot init # creates the configuration file in the current directory
```
- Create a Twitter account for your bot.
- Obtain OAuth tokens to authorize the bot for the new Twitter account:
    - visit https://apps.twitter.com
    - Click "Create New App" and enter the required information.
    - In the "Permissions" tab, change the app permissions to allow direct messages.
    - In the "Keys and Access Tokens" tab, create access tokens by clicking "Create my access token".
    - Replace the `Consumer Key`, `Consumer Secret`, `AccessToken`, and `AccessSecret` in the config file with the corresponding values in the "Keys and Access Tokens" tab.
    - Replace the `Handle` in the config file with the handle of your bot's Twitter account.

### Run the bot
```
⇒  coniksbot run  # run the CONIKS bot
```

## Disclaimer
Please keep in mind that this CONIKS account verification bot implementation is under active development. The repository may contain experimental features that aren't fully tested. We recommend using a [tagged release](https://github.com/coniks-sys/coniks-go/releases).
