package bots

import (
	"github.com/coniks-sys/coniks-go/application"
)

// A TwitterConfig contains the address of the named UNIX socket
// through which the bot and the CONIKS server communicate,
// the OAuth information needed to authenticate the bot with Twitter,
// and the bot's reserved Twitter handle. These values are specified
// in a configuration file, which is read at initialization time.
type TwitterConfig struct {
	*application.ConfigService
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

var _ application.AppConfig = (*TwitterConfig)(nil)

// NewTwitterConfig initializes a new Twitter registration bot configuration
// with the given server address, Twitter handle, and OAuth credentials.
func NewTwitterConfig(addr, handle string, oauth TwitterOAuth) *TwitterConfig {
	var conf = TwitterConfig{
		CONIKSAddress: addr,
		Handle:        handle,
		TwitterOAuth:  oauth,
	}

	return &conf
}

// Load initializes a Twitter registration proxy configuration from the
// corresponding config file.
func (conf *TwitterConfig) Load(file string) error {
	conf.ConfigService = application.NewConfigService(conf)
	return conf.ConfigService.Load(file)
}

// Save writes a Twitter registration proxy configuration to the
// given config file.
func (conf *TwitterConfig) Save(file string) error {
	conf.ConfigService = application.NewConfigService(conf)
	return conf.ConfigService.Save(file)
}
