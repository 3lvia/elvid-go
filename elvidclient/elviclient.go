// Package elvidclient provides functionality for retrieving a token from the Elvid API. New tokens are retrieved
// automatically and communicated out of this package through a channel.
//
// NOTE: This package takes a dependency on opentelemetry (go.opentelemetry.io/otel), meaning that the caller of this
// package must initialize opentelemetry before using this package.
package elvidclient

import (
	"context"
	"net/http"
)

const defaultMinimumResolvedSeconds = 10

// Start initializes this package with the given options, and starts the internal functionality of the package.
func Start(ctx context.Context, opts ...Option) <-chan string {
	collector := &optionsCollector{}
	for _, opt := range opts {
		opt(collector)
	}

	client := collector.client
	if client == nil {
		client = http.DefaultClient
	}

	ch := make(chan string)

	s := newStarter(collector, client, defaultMinimumResolvedSeconds)
	go s.start(ctx, ch)

	return ch
}
