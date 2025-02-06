package main

// Config struct
type Config struct {
	Webhook        string
	BrowserStealer bool
	tokenStealer   bool
	Startup        bool
	DiscordInject  bool
	AntiDebug      bool
	CheckProcess   bool
	CheckSystem    bool
	Checknetwork   bool
}

// NewConfig func
func NewConfig() *Config {
	return &Config{
		Webhook:        "",
		BrowserStealer: true,  // This is true by default
		tokenStealer:   true,  // This is true by default
		Startup:        true,  // This is true by default
		DiscordInject:  true,  // This is true by default
		AntiDebug:      true,  // This is true by default
		CheckProcess:   false, // This is false by default
		CheckSystem:    true,  // This is true by default
		Checknetwork:   true,  // This is true by default
	}
}
