package elvidserver

import "net/http"

type optionsCollector struct {
	jwkString string
	jwkURL    string
	client    *http.Client
	scope     string
}

// Option is a function that can be used to configure this package.
type Option func(*optionsCollector)

// WithJWK configures the JWK that is used to validate the JWT. Either this option or WithJWKURL must be provided.
func WithJWK(jwkString string) Option {
	return func(c *optionsCollector) {
		c.jwkString = jwkString
	}
}

// WithJWKURL configures the URL that is used to fetch the JWK that is used to validate the JWT. Either this option or
// WithJWK must be provided.
func WithJWKURL(jwkURL string) Option {
	return func(c *optionsCollector) {
		c.jwkURL = jwkURL
	}
}

// WithHTTPClient configures the HTTP client that is used to fetch the JWK. If this option is not provided, the default
// HTTP client is used. This option is only relevant if WithJWKURL is provided, and is mostly used for testing.
func WithHTTPClient(client *http.Client) Option {
	return func(c *optionsCollector) {
		c.client = client
	}
}

// WithScope configures the scope that is required for the JWT to be valid. This option is required.
func WithScope(scope string) Option {
	return func(c *optionsCollector) {
		c.scope = scope
	}
}
