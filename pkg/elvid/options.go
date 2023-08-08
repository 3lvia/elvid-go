package elvid

import (
	"net/http"
	"os"
	"time"
)

const (
	discoveryEndpoint = "/.well-known/openid-configuration"
)

type Config struct {
	client *http.Client

	cert      string
	address   string
	discovery string

	jwksConfig *JWKSConfig
}

type JWKSConfig struct {
	RefreshInterval     time.Duration
	RefreshRateLimit    time.Duration
	RefreshTimeout      time.Duration
	RefreshErrorHandler func(err error)
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

	if c.jwksConfig == nil {
		c.jwksConfig = &JWKSConfig{
			RefreshInterval:     time.Hour,
			RefreshRateLimit:    time.Minute * 5,
			RefreshTimeout:      time.Second * 10,
			RefreshErrorHandler: nil,
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

// WithClient lets you set your own http.Client that will be used internally.
// Make sure the client is configured to be secure since unsecure clients can
// pose security risks.
func WithClient(client *http.Client) Option {
	return optionFunc(func(c *Config) {
		c.client = client
	})
}

// WithAddress sets the base url to use to access ElvID.
// If this is left empty, it will be loaded from ELVID_BASE_URL env var.
func WithAddress(address string) Option {
	return optionFunc(func(c *Config) {
		c.address = address
	})
}

// WithDiscovery sets the discovery uri to use to access ElvID (appended to address).
// If this is left empty, it will be loaded from ELVID_DISCOVERY env var.
// Otherwise, it will use the standard endpoint for loading openid connect configuration.
// See https://en.wikipedia.org/wiki/Well-known_URI for more information.
func WithDiscovery(discovery string) Option {
	return optionFunc(func(c *Config) {
		c.discovery = discovery
	})
}

// WithJWKS lets you set timings for the background task to refresh JWKS data.
// See https://pkg.go.dev/github.com/MicahParks/keyfunc/v2#Options
func WithJWKS(jwks JWKSConfig) Option {
	return optionFunc(func(c *Config) {
		c.jwksConfig = &jwks
	})
}