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
	*application.CommonConfig
	CONIKSAddress string `toml:"coniks_address"`
	TwitterOAuth  `toml:"twitter_oauth"`
	Handle        string `toml:"twitter_bot_handle"`
}

var _ application.AppConfig = (*TwitterConfig)(nil)

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

// NewTwitterConfig initializes a new Twitter registration bot configuration
// at the given file path, with the config encoding, server address, Twitter handle,
// OAuth credentials.
func NewTwitterConfig(file, encoding, addr, handle string,
	oauth TwitterOAuth) *TwitterConfig {
	var conf = TwitterConfig{
		CommonConfig:  application.NewCommonConfig(file, encoding, nil),
		CONIKSAddress: addr,
		Handle:        handle,
		TwitterOAuth:  oauth,
	}

	return &conf
}

// Load initializes a Twitter registration proxy configuration
// at the given file path using the given encoding.
func (conf *TwitterConfig) Load(file, encoding string) error {
	conf.CommonConfig = application.NewCommonConfig(file, encoding, nil)
	return conf.GetLoader().Decode(conf)
}

// Save writes a Twitter registration proxy configuration
// using the given encoding.
func (conf *TwitterConfig) Save() error {
	return conf.GetLoader().Encode(conf)
}

// Path returns the Twitter configuration's file path.
func (conf *TwitterConfig) GetPath() string {
	return conf.Path
}
