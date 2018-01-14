// A registration proxy for Twitter accounts that implements the
// CONIKS account verification Bot interface.

package bots

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/coniks-sys/coniks-go/application"
	"github.com/coniks-sys/coniks-go/protocol"
	"github.com/dghubble/go-twitter/twitter"
	"github.com/dghubble/oauth1"
)

// A TwitterBot is an account verification bot for
// CONIKS clients registering Twitter usernames
// with a CONIKS key server.
//
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

// NewTwitterBot constructs a new account verification bot for Twitter
// accounts that implements the Bot interface.
//
// NewTwitterBot checks that the CONIKS key server
// is live, and authenticates the bot's Twitter client via OAuth.
// If any of these steps fail, NewTwitterBot returns a (nil, error)
// tuple. Otherwise, it returns a TwitterBot struct
// with the appropriate values obtained during the setup.
func NewTwitterBot(conf *TwitterConfig) (Bot, error) {
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
		return nil, fmt.Errorf("Could not authenticate you")
	}

	bot := new(TwitterBot)
	bot.client = client
	bot.coniksAddress = conf.CONIKSAddress
	bot.handle = conf.Handle

	bot.deleteOldDMs()

	return bot, nil
}

// Run implements the main functionality of a Twitter registration proxy.
// It listens for a Twitter direct message (DM) sent to the bot's
// reserved handle and calls HandleRegistration() upon receiving a valid
// DM sent by a CONIKS client connected to a Twitter account.
// The result of HandleRegistration() is returned to the CONIKS client
// via DM.
func (bot *TwitterBot) Run() {
	demux := twitter.NewSwitchDemux()
	demux.DM = func(requestDM *twitter.DirectMessage) {
		if strings.EqualFold(requestDM.SenderScreenName, bot.handle) {
			return
		}
		var responseDM *twitter.DirectMessage
		var err error
		// check if received DM has proper format
		if strings.HasPrefix(requestDM.Text, messagePrefix) {
			msg := strings.TrimPrefix(requestDM.Text, messagePrefix)
			res := bot.HandleRegistration(requestDM.SenderScreenName, []byte(msg))
			// Hackity, hack, hack!
			// Twitter APIs probably don't want people call them so fast
			time.Sleep(5 * time.Second)
			responseDM, err = bot.sendDM(requestDM.SenderScreenName, messagePrefix+res)
			if err != nil {
				log.Printf("[registration bot] " + err.Error())
			}
		}
		bot.deleteRequestDMs(requestDM, responseDM)
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
// corresponding CONIKS key server if the Twitter account for username is valid.
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
	req, err := application.UnmarshalRequest(msg)
	if err != nil {
		invalid = true
	} else {
		request, ok := req.Request.(*protocol.RegistrationRequest)
		if req.Type != protocol.RegistrationType || !ok ||
			// FIXME: Agree on a convention in issues #17 / #30
			!strings.EqualFold(strings.ToLower(username)+"@twitter", request.Username) {
			invalid = true
		}
	}
	if invalid {
		log.Println("[registration bot] Malformed client request")
		res, err := application.MarshalResponse(
			protocol.NewErrorResponse(protocol.ErrMalformedMessage))
		if err != nil {
			panic(err)
		}
		return string(res)
	}

	// send request to coniks server
	res, err := SendRequestToCONIKS(bot.coniksAddress, msg)
	if err != nil {
		log.Println("[registration bot] " + err.Error())
		res, err := application.MarshalResponse(
			protocol.NewErrorResponse(protocol.ErrDirectory))
		if err != nil {
			panic(err)
		}
		return string(res)
	}
	return string(res)
}

// sendDM sends a Twitter direct message msg to the given Twitter screenname.
// The sender screenname should be set to the bot's reserved Twitter handle.
func (bot *TwitterBot) sendDM(screenname, msg string) (*twitter.DirectMessage, error) {
	params := &twitter.DirectMessageNewParams{ScreenName: screenname, Text: msg}
	dm, _, err := bot.client.DirectMessages.New(params)
	return dm, err
}

// deleteOldDMs deletes all prior DMs before the bot runs.
func (bot *TwitterBot) deleteOldDMs() {
	log.Println("[registration bot] Deleting old DMs ...")
	// GET /direct_messages returns at most 200 recent DMs.
	// See https://dev.twitter.com/rest/reference/get/direct_messages
	params := &twitter.DirectMessageGetParams{Count: 200}
	for {
		dms, _, err := bot.client.DirectMessages.Get(params)
		if err != nil {
			log.Println("[registration bot] Cannot get Twitter bot's DMs. Error: " + err.Error())
		}
		if len(dms) == 0 {
			log.Println("[registration bot] Deleted all old DMs")
			return
		}
		for i := 0; i < len(dms); i++ {
			_, _, err = bot.client.DirectMessages.Destroy(dms[i].ID, nil)
			if err != nil {
				log.Println("[registration bot] Could not remove Twitter bot's DM. Error: " + err.Error())
			}
		}
	}
}

// deleteRequestDMs waits for 5 mins and
// then removes the request and response DMs.
// This should be called each time the bot handles a registration request.
func (bot *TwitterBot) deleteRequestDMs(requestDM, responseDM *twitter.DirectMessage) {
	timer := time.NewTimer(time.Second * 300)

	go func() {
		defer timer.Stop()
		<-timer.C
		_, _, err := bot.client.DirectMessages.Destroy(requestDM.ID, nil)
		if err != nil {
			log.Println("[registration bot] Could not remove Twitter bot's DM. Error: " + err.Error())
		}
		if responseDM != nil {
			_, _, err = bot.client.DirectMessages.Destroy(responseDM.ID, nil)
			if err != nil {
				log.Println("[registration bot] Could not remove Twitter bot's DM. Error: " + err.Error())
			}
		}
	}()
}
