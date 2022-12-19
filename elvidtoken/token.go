// Package elvidtoken implements middleware for validating JWT tokens. The package must be initialized with a valid JWK URL
// (or a concrete JWK string) and a scope. All http.HandlerFuncs that the client application wants to protect with a
// JWT token must be wrapped with the Wrap function. The wrapped function will validate the token and return an error
// if the token is invalid or if the token does not have the required scope.
//
// Sample usage:
//
//	if err := elvidtoken.Init(elvidtoken.WithJWKURL(jwkURL), elvidtoken.WithScope("hes-extensions.machineaccess")); err != nil {
//		panic(err)
//	}
//
//	h := elvidtoken.Wrap(myHandlerFunc)
//	if err := http.ListenAndServe(":8080", h); err != nil {
//		panic(err)
//	}
package elvidtoken

import (
	"crypto/rsa"
	"errors"
	"net/http"
)

var currentKey *rsa.PublicKey
var currentClient *http.Client
var currentScope string

// Init initializes the token package. This function must be called before any other function in this package.
func Init(opts ...Option) error {
	collector := &optionsCollector{}
	for _, opt := range opts {
		opt(collector)
	}

	currentClient = collector.client
	if currentClient == nil {
		currentClient = http.DefaultClient
	}

	currentScope = collector.scope
	if currentScope == "" {
		return errors.New("missing scope")
	}

	jwkFunc := func(b []byte) error {
		key, err := parseJWK(b)
		if err != nil {
			return err
		}
		currentKey = key
		return nil
	}

	if collector.jwkString != "" {
		if err := jwkFunc([]byte(collector.jwkString)); err != nil {
			return err
		}
	}

	if collector.jwkURL == "" {
		return errors.New("no JWK provided")
	}

	jwkString, err := getJWK(collector.jwkURL)
	if err != nil {
		return err
	}

	return jwkFunc(jwkString)
}
