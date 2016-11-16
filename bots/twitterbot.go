// An account verification proxy for Twitter accounts that implements the CONIKS
// registration Bot interface.

package bots

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coniks-sys/coniks-go/keyserver"
	p "github.com/coniks-sys/coniks-go/protocol"
	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
)

// A TwitterBot is an account verification proxy for
// CONIKS clients registering Twitter usernames
// with a CONIKS key server.
// A TwitterBot maintains information about a
// twitter client and stream, the address of its
// corresponding CONIKS server, and its reserved
// Twitter handle.
type TwitterBot struct {
	client        *twitter.Client
	stream        *twitter.Stream
	coniksAddress string
	handle        string
}

var _ Bot = (*TwitterBot)(nil)

// A TwitterConfig contains the address of the named UNIX socket
// through which the bot and the CONIKS server communicate,
// the OAuth information needed to authenticate the bot with Twitter,
// and the bot's reserved Twitter handle. These values are specified
// in a configuration file, which is read at initialization time.
type TwitterConfig struct {
	CONIKSAddress string `toml:"coniks_address"`
	TwitterOAuth  `toml:"twitter_oauth"`
	Handle        string `toml:"twitter_bot_handle"`
}

// A TwitterOAuth contains the four secret values needed to authenticate
// the bot with Twitter. These values are unique to each application
// that uses the Twitter API to access an account's feed and direct
// messages, and must be generated via Twitter's developer portal.
type TwitterOAuth struct {
	ConsumerKey    string
	ConsumerSecret string
	AccessToken    string
	AccessSecret   string
}

// NewTwitterBot creates a new TwitterBot that implements the Bot
// interface.
// NewTwitterBot loads the TwitterConfig for this bot from the
// corresponding config file, checks that the CONIKS key server
// is live, and authenticates the bot's Twitter client via OAuth.
// If any of these steps fail, NewTwitterBot returns a (nil, error)
// tuple. Otherwise, it returns a TwitterBot struct
// with the appropriate values obtained during the setup.
func NewTwitterBot(path string) (Bot, error) {
	var conf TwitterConfig
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// Notify if the CONIKS key server is down
	if _, err := os.Stat(conf.CONIKSAddress); os.IsNotExist(err) {
		return nil, fmt.Errorf("CONIKS Key Server is down")
	}

	auth := conf.TwitterOAuth
	config := oauth1.NewConfig(auth.ConsumerKey, auth.ConsumerSecret)
	token := oauth1.NewToken(auth.AccessToken, auth.AccessSecret)
	// OAuth1 http.Client will automatically authorize Requests
	httpClient := config.Client(oauth1.NoContext, token)

	// Twitter Client
	client := twitter.NewClient(httpClient)
	// Verify the tokens
	handle, _, err := client.Accounts.VerifyCredentials(
		&twitter.AccountVerifyParams{
			IncludeEntities: twitter.Bool(false),
			IncludeEmail:    twitter.Bool(true),
		})
	if err != nil ||
		handle.ScreenName != conf.Handle {
		return nil, fmt.Errorf("Could not authenticate you.")
	}

	bot := new(TwitterBot)
	bot.client = client
	bot.coniksAddress = conf.CONIKSAddress
	bot.handle = conf.Handle

	return bot, nil
}

// Run implements the main functionality of the TwitterBot bot.
// It listens for a Twitter direct message (DM) sent to the bot's
// reserved handle and calls HandleRegistration() upon receiving a valid
// DM sent by a CONIKS client connected to a Twitter account.
// The result of HandleRegistration() is returned to the CONIKS client
// via DM.
func (bot *TwitterBot) Run() {
	demux := twitter.NewSwitchDemux()
	demux.DM = func(dm *twitter.DirectMessage) {
		if strings.EqualFold(dm.SenderScreenName, bot.handle) {
			return
		}
		// check if received DM has proper format
		if strings.HasPrefix(dm.Text, messagePrefix) {
			msg := strings.TrimPrefix(dm.Text, messagePrefix)
			res := bot.HandleRegistration(dm.SenderScreenName, []byte(msg))
			// Hackity, hack, hack!
			// Twitter APIs probably doesn't want people call them so fast
			time.Sleep(5 * time.Second)
			err := bot.SendDM(dm.SenderScreenName, messagePrefix+res)
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

// Stop closes the bot's open stream through which it communicates with Twitter.
func (bot *TwitterBot) Stop() {
	bot.stream.Stop()
}

// HandleRegistration verifies the authenticity of a CONIKS registration
// request msg for a Twitter user, and forwards this request to the bot's
// corresponding CONIKS key server the Twitter account for username is valid.
//
// HandleRegistration() validates a registration request sent by a CONIKS client
// on behalf of the Twitter user via Twitter DM.
// It does so by comparing the username indicated in the request with the
// Twitter handle which sent the DM. HandleRegistration() forwards the registration
// request to the CONIKS server via SendRequestToCONIKS() if username matches
// request.Username, and returns the server's response as a string.
// See https://godoc.org/github.com/coniks-sys/coniks-go/protocol/#ConiksDirectory.Register
// for details on the possible server responses.
func (bot *TwitterBot) HandleRegistration(username string, msg []byte) string {
	// validate request message
	invalid := false
	req, err := keyserver.UnmarshalRequest(msg)
	if err != nil {
		invalid = true
	} else {
		request, ok := req.Request.(*p.RegistrationRequest)
		if req.Type != p.RegistrationType || !ok ||
			// FIXME: Agree on a convention in issues #17 / #30
			!strings.EqualFold(strings.ToLower(username)+"@twitter", request.Username) {
			invalid = true
		}
	}
	if invalid {
		log.Println("[registration bot] Malformed client request")
		res, err := keyserver.MarshalResponse(
			p.NewErrorResponse(p.ErrMalformedClientMessage))
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
			p.NewErrorResponse(p.ErrDirectory))
		if err != nil {
			panic(err)
		}
		return string(res)
	}
	return string(res)
}

// SendDM sends a Twitter direct message msg to the given Twitter screenname.
// The sender screenname is set to the bot's reserved Twitter handle.
func (bot *TwitterBot) SendDM(screenname, msg string) error {
	params := &twitter.DirectMessageNewParams{ScreenName: screenname, Text: msg}
	_, _, err := bot.client.DirectMessages.New(params)
	return err
}
