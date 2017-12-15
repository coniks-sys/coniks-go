package cmd

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/coniks-sys/coniks-go/application"
	clientapp "github.com/coniks-sys/coniks-go/application/client"
	"github.com/coniks-sys/coniks-go/application/testutil"
	"github.com/coniks-sys/coniks-go/cli"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/coniks-sys/coniks-go/protocol/client"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

const help = "- register [name] [key]:\r\n" +
	"	Register a new name-to-key binding on the CONIKS-server.\r\n" +
	"- lookup [name]:\r\n" +
	"	Lookup the key of some known contact or your own bindings.\r\n" +
	"- enable timestamp:\r\n" +
	"	Print timestamp of format <15:04:05.999999999> along with the result.\r\n" +
	"- disable timestamp:\r\n" +
	"	Disable timestamp printing.\r\n" +
	"- help:\r\n" +
	"	Display this message.\r\n" +
	"- exit, q:\r\n" +
	"	Close the REPL and exit the client."

var runCmd = cli.NewRunCommand("CONIKS test client", "Run gives you a REPL, so that you can invoke commands to perform CONIKS operations including registration and key lookup. Currently, it supports:\n"+help, run)

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "config.toml",
		"Config file for the client (contains the server's initial public key etc).")
	runCmd.Flags().BoolP("debug", "d", false, "Turn on debugging mode")
}

func run(cmd *cobra.Command, args []string) {
	isDebugging, _ := strconv.ParseBool(cmd.Flag("debug").Value.String())
	conf := loadConfigOrExit(cmd)
	cc := client.New(nil, true, conf.SigningPubKey)

	state, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(int(os.Stdin.Fd()), state)
	term := terminal.NewTerminal(os.Stdin, "coniks-client> ")
	for {
		line, err := term.ReadLine()
		if err != nil {
			writeLineInRawMode(term, err.Error(), isDebugging)
			return
		}

		args := strings.Fields(line)
		if len(args) < 1 {
			writeLineInRawMode(term, `[!] Type "help" for more information.`, isDebugging)
			continue
		}
		cmd := args[0]

		switch cmd {
		case "exit", "q":
			writeLineInRawMode(term, "[+] See ya.", isDebugging)
			return
		case "help":
			writeLineInRawMode(term, help, false) // turn off debugging mode for this command
		case "enable", "disable":
			if len(args) != 2 {
				writeLineInRawMode(term, "[!] Unrecognized command: "+line, isDebugging)
				continue
			}
			switch args[1] {
			case "timestamp":
				if cmd == "enable" {
					isDebugging = true
				} else {
					isDebugging = false
				}
			default:
				writeLineInRawMode(term, "[!] Unrecognized command: "+line, isDebugging)
			}
		case "register":
			if len(args) != 3 {
				writeLineInRawMode(term, "[!] Incorrect number of args to register.", isDebugging)
				continue
			}
			msg := register(cc, conf, args[1], args[2])
			writeLineInRawMode(term, "[+] "+msg, isDebugging)
		case "lookup":
			if len(args) != 2 {
				writeLineInRawMode(term, "[!] Incorrect number of args to lookup.", isDebugging)
				continue
			}
			msg := keyLookup(cc, conf, args[1])
			writeLineInRawMode(term, "[+] "+msg, isDebugging)
		default:
			writeLineInRawMode(term, "[!] Unrecognized command: "+cmd, isDebugging)
		}
	}
}

func register(cc *client.ConsistencyChecks, conf *clientapp.Config, name string, key string) string {
	req, err := clientapp.CreateRegistrationMsg(name, []byte(key))
	if err != nil {
		return ("Couldn't marshal registration request!")
	}

	var res []byte
	regAddress := conf.RegAddress
	if regAddress == "" {
		// fallback to conf.Address if empty
		regAddress = conf.Address
	}
	u, _ := url.Parse(regAddress)
	switch u.Scheme {
	case "tcp":
		res, err = testutil.NewTCPClient(req, regAddress)
		if err != nil {
			return ("Error while receiving response: " + err.Error())
		}
	case "unix":
		res, err = testutil.NewUnixClient(req, regAddress)
		if err != nil {
			return ("Error while receiving response: " + err.Error())
		}
	default:
		return ("Invalid config!")
	}

	response := application.UnmarshalResponse(protocol.RegistrationType, res)
	err = cc.HandleResponse(protocol.RegistrationType, response, name, []byte(key))
	switch err {
	case protocol.CheckBadSTR:
		// FIXME: remove me
		return ("Error: " + err.Error() + ". Maybe the client missed an epoch in between two commands, monitoring isn't supported yet.")
	case nil:
		switch response.Error {
		case protocol.ReqSuccess:
			return ("Succesfully registered name: " + name)
		case protocol.ReqNameExisted:
			return ("Name is already registered.")
		}
	case protocol.CheckBindingsDiffer:
		switch response.Error {
		case protocol.ReqNameExisted:
			return (`Are you trying to update your binding? Unfortunately, KeyChange isn't supported yet.`)
		case protocol.ReqSuccess:
			recvKey, err := response.GetKey()
			if err != nil {
				return ("Oops! The server snuck in some other key. However, I cannot get the key from the response, error: " + err.Error())
			}
			return ("Oops! The server snuck in some other key. [" + string(recvKey) + "] was registered instead of [" + string(key) + "]")
		}
	default:
		return ("Error: " + err.Error())
	}
	return ""
}

func keyLookup(cc *client.ConsistencyChecks, conf *clientapp.Config, name string) string {
	req, err := clientapp.CreateKeyLookupMsg(name)
	if err != nil {
		return ("Couldn't marshal key lookup request!")
	}

	var res []byte
	u, _ := url.Parse(conf.Address)
	switch u.Scheme {
	case "tcp":
		res, err = testutil.NewTCPClient(req, conf.Address)
		if err != nil {
			return ("Error while receiving response: " + err.Error())
		}
	case "unix":
		res, err = testutil.NewUnixClient(req, conf.Address)
		if err != nil {
			return ("Error while receiving response: " + err.Error())
		}
	default:
		return ("Invalid config!")
	}

	response := application.UnmarshalResponse(protocol.KeyLookupType, res)
	if key, ok := cc.Bindings[name]; ok {
		err = cc.HandleResponse(protocol.KeyLookupType, response, name, []byte(key))
	} else {
		err = cc.HandleResponse(protocol.KeyLookupType, response, name, nil)
	}
	switch err {
	case protocol.CheckBadSTR:
		// FIXME: remove me
		return ("Error: " + err.Error() + ". Maybe the client missed an epoch in between two commands, monitoring isn't supported yet.")
	case nil:
		switch response.Error {
		case protocol.ReqSuccess:
			key, err := response.GetKey()
			if err != nil {
				return ("Cannot get the key from the response, error: " + err.Error())
			}
			return ("Found! Key bound to name is: [" + string(key) + "]")
		case protocol.ReqNameNotFound:
			return ("Name isn't registered.")
		}
	default:
		return ("Error: " + err.Error())
	}
	return ""
}
