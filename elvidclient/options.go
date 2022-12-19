package elvidclient

import (
	"net/http"
)

type optionsCollector struct {
	client            *http.Client
	tokenClientID     string
	tokenClientSecret string
	tokenEndpoint     string
}

// Option is a function that can be used to configure the callback package.
type Option func(*optionsCollector)

// WithHTTPClient sets the HTTP client to use when sending callback requests. This is useful for testing, and
// it is not necessary to call this function in production; the default HTTP client will be used.
func WithHTTPClient(client *http.Client) Option {
	return func(o *optionsCollector) {
		o.client = client
	}
}

// WithTokenClient sets the client ID and client secret to use when requesting a token from ElvID.
func WithTokenClient(clientID, clientSecret, tokenEndpoint string) Option {
	return func(o *optionsCollector) {
		o.tokenClientID = clientID
		o.tokenClientSecret = clientSecret
		o.tokenEndpoint = tokenEndpoint
	}
}
