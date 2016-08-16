package bots

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/keyserver"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
)

type TwitterBot struct {
	client        *twitter.Client
	stream        *twitter.Stream
	coniksAddress string
	handle        string
}

var _ Bot = (*TwitterBot)(nil)

type TwitterConfig struct {
	CONIKSAddress string `toml:"coniks_address"`
	TwitterOAuth  `toml:"twitter_oauth"`
	Handle        string `toml:"twitter_bot_handle"`
}

type TwitterOAuth struct {
	ConsumerKey    string
	ConsumerSecret string
	AccessToken    string
	AccessSecret   string
}

func NewTwitterBot(path string) (Bot, error) {
	var conf TwitterConfig
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	auth := conf.TwitterOAuth
	config := oauth1.NewConfig(auth.ConsumerKey, auth.ConsumerSecret)
	token := oauth1.NewToken(auth.AccessToken, auth.AccessSecret)
	// OAuth1 http.Client will automatically authorize Requests
	httpClient := config.Client(oauth1.NoContext, token)

	// Twitter Client
	client := twitter.NewClient(httpClient)

	bot := new(TwitterBot)
	bot.client = client
	bot.coniksAddress = conf.CONIKSAddress
	bot.handle = conf.Handle

	return bot, nil
}

func (bot *TwitterBot) Run() {
	demux := twitter.NewSwitchDemux()
	demux.DM = func(dm *twitter.DirectMessage) {
		if strings.EqualFold(dm.SenderScreenName, bot.handle) {
			return
		}
		// check if received DM has proper format
		if strings.HasPrefix(dm.Text, "?CONIKS?") {
			msg := strings.TrimPrefix(dm.Text, "?CONIKS?")
			res := bot.HandleRegistration(dm.SenderScreenName, []byte(msg))
			// Hackity, hack, hack!
			// Twitter APIs probably doesn't want people call them so fast
			time.Sleep(5 * time.Second)
			err := bot.SendDM(dm.SenderScreenName, "?CONIKS?"+res)
			if err != nil {
				log.Printf("[registration bot] " + err.Error())
			}
		}
	}

	userParams := &twitter.StreamUserParams{
		StallWarnings: twitter.Bool(true),
	}
	stream, err := bot.client.Streams.User(userParams)
	if err != nil {
		log.Fatal(err)
	}
	bot.stream = stream

	// Receive messages until stopped or stream quits
	go demux.HandleChan(stream.Messages)
}

func (bot *TwitterBot) Stop() {
	bot.stream.Stop()
}

func (bot *TwitterBot) HandleRegistration(username string, msg []byte) string {
	// validate request message
	invalid := false
	req, err := keyserver.UnmarshalRequest(msg)
	if err != nil {
		invalid = true
	} else {
		request, ok := req.Request.(*p.RegistrationRequest)
		if req.Type != p.RegistrationType || !ok ||
			// issue: https://github.com/coniks-sys/coniks-go/issues/30
			!strings.EqualFold(strings.ToLower(username)+"@twitter", request.Username) {
			invalid = true
		}
	}
	if invalid {
		log.Println("[registration bot] Malformed client request")
		res, err := keyserver.MarshalResponse(
			p.NewErrorResponse(p.ErrorMalformedClientMessage))
		if err != nil {
			panic(err)
		}
		return string(res)
	}

	// send request to coniks server
	res, err := SendRequestToCONIKS(bot.coniksAddress, msg)
	if err != nil {
		log.Println("[registration bot] " + err.Error())
		res, err := keyserver.MarshalResponse(
			p.NewErrorResponse(p.ErrorDirectory))
		if err != nil {
			panic(err)
		}
		return string(res)
	}
	return string(res)
}

func (bot *TwitterBot) SendDM(screenname, msg string) error {
	params := &twitter.DirectMessageNewParams{ScreenName: screenname, Text: msg}
	_, _, err := bot.client.DirectMessages.New(params)
	return err
}
