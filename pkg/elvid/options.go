package elvid

import "os"

const (
	discoveryEndpoint = "/.well-known/openid-configuration"
)

type Config struct {
	cert      string
	address   string
	discovery string
}

func (c *Config) Cert() string {
	if c.cert == "" {
		c.cert = os.Getenv("ELVID_CACERT")
	}
	return c.cert
}

func (c *Config) Address() string {
	if c.address == "" {
		c.address = os.Getenv("ELVID_BASE_URL")
	}
	return c.address
}

func (c *Config) Discovery() string {
	if c.discovery == "" {
		c.discovery = os.Getenv("ELVID_DISCOVERY")
	}
	if c.discovery == "" {
		c.discovery = discoveryEndpoint
	}
	return c.discovery
}

func NewConfig(opts ...Option) Config {
	var config Config
	for _, option := range opts {
		option.apply(&config)
	}
	return config
}

type Option interface {
	apply(*Config)
}

type optionFunc func(*Config)

func (fn optionFunc) apply(cfg *Config) {
	fn(cfg)
}

func WithAddress(address string) Option {
	return optionFunc(func(c *Config) {
		c.address = address
	})
}

func WithDiscovery(discovery string) Option {
	return optionFunc(func(c *Config) {
		c.discovery = discovery
	})
}