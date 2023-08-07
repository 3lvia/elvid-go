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
	return c.cert
}

func (c *Config) Address() string {
	return c.address
}

func (c *Config) Discovery() string {
	return c.discovery
}

func newConfig(opts ...Option) Config {
	var c Config
	for _, option := range opts {
		option.apply(&c)
	}

	if c.cert == "" {
		c.cert = os.Getenv("ELVID_CACERT")
	}

	if c.address == "" {
		c.address = os.Getenv("ELVID_BASE_URL")
	}

	if c.discovery == "" {
		c.discovery = os.Getenv("ELVID_DISCOVERY")

		if c.discovery == "" {
			c.discovery = discoveryEndpoint
		}
	}
	return c
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