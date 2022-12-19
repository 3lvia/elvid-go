package main

import (
	"github.com/3lvia/elvid-go/token"
	"net/http"
)

const jwkURL = `https://elvid.test-elvia.io/.well-known/openid-configuration/jwks`

func main() {
	if err := token.Init(token.WithJWKURL(jwkURL), token.WithScope("hes-extensions.machineaccess")); err != nil {
		panic(err)
	}

	h := token.Wrap(myHandlerFunc)

	go http.Handle("/", h)

	if err := http.ListenAndServe(":8080", h); err != nil {
		panic(err)
	}
}

func myHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`hello world`))
}
