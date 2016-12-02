package cmd

import (
	"log"
	"net/url"
	"os"

	"github.com/coniks-sys/coniks-go/client"
	"github.com/coniks-sys/coniks-go/keyserver/testutil"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the test client.",
	Long: `run gives you a REPL, so that you can invoke commands to perform CONIKS operations including registration and key lookup. Currently, run supports:
	- register:
		Register a new name-to-key binding on the CONIKS-server. You will be asked to input a username and a public key for the binding.
		The username and the key are separated by new line character (ENTER key).
	- lookup:
		Lookup the key of some known contact or your own bindings.
	- exit:
		Close the REPL and exit the client.`,
	Run: func(cmd *cobra.Command, args []string) {
		run(cmd)
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
	runCmd.Flags().StringP("config", "c", "config.toml",
		"Config file for the client (contains the server's initial public key etc).")
}

func run(cmd *cobra.Command) {
	conf := loadConfigOrExit(cmd)
	cc := p.NewCC(nil, true, conf.SigningPubKey)

	state, err := terminal.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	defer terminal.Restore(int(os.Stdin.Fd()), state)
	term := terminal.NewTerminal(os.Stdin, "> ")
	for {
		term.SetPrompt("> ")
		cmd, err := term.ReadLine()
		if err != nil {
			writeLineInRawMode(term, "[!] Unknown command.")
			continue
		}
		term.SetPrompt(">> ")
		switch cmd {
		case "exit":
			writeLineInRawMode(term, "[+] See ya.")
			return
		case "register":
			writeLineInRawMode(term, ">> Enter your name & public key:")
			name, err := term.ReadLine()
			if err != nil || name == "" {
				writeLineInRawMode(term, "[!] Cannot read your name.")
				continue
			}
			key, err := term.ReadLine()
			if err != nil || key == "" {
				writeLineInRawMode(term, "[!] Cannot read your key.")
				continue
			}
			msg := register(cc, conf, name, key)
			writeLineInRawMode(term, "[+] "+msg)
		case "lookup":
			writeLineInRawMode(term, ">> Enter the lookup name:")
			name, err := term.ReadLine()
			if err != nil {
				writeLineInRawMode(term, "[!] Cannot read your name.")
				continue
			}
			msg := keyLookup(cc, conf, name)
			writeLineInRawMode(term, "[+] "+msg)
		default:
			writeLineInRawMode(term, "[!] Unrecognized command: "+cmd)
			continue
		}
	}
}

func register(cc *p.ConsistencyChecks, conf *client.Config, name string, key string) string {
	req, err := client.CreateRegistrationMsg(name, []byte(key))
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

	response := client.UnmarshalResponse(p.RegistrationType, res)
	err = cc.HandleResponse(p.RegistrationType, response, name, []byte(key))
	switch err {
	case p.CheckPassed:
		switch response.Error {
		case p.ReqSuccess:
			return ("Succesfully registered name: " + name)
		case p.ReqNameExisted:
			return ("Name is already registered.")
		}
	case p.CheckBindingsDiffer:
		switch response.Error {
		case p.ReqNameExisted:
			return (`Are you trying to update your binding? Unfortunately, KeyChange isn't supported yet.`)
		case p.ReqSuccess:
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

func keyLookup(cc *p.ConsistencyChecks, conf *client.Config, name string) string {
	req, err := client.CreateKeyLookupMsg(name)
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

	response := client.UnmarshalResponse(p.RegistrationType, res)
	if key, ok := cc.Bindings[name]; ok {
		err = cc.HandleResponse(p.KeyLookupType, response, name, []byte(key))
	} else {
		err = cc.HandleResponse(p.KeyLookupType, response, name, nil)
	}
	switch err {
	case p.CheckPassed:
		switch response.Error {
		case p.ReqSuccess:
			key, err := response.GetKey()
			if err != nil {
				return ("Cannot get the key from the response, error: " + err.Error())
			}
			return ("Success! Key bound to name is: [" + string(key) + "]")
		case p.ReqNameNotFound:
			return ("Name isn't registered.")
		}
	default:
		return ("Error: " + err.Error())
	}
	return ""
}
