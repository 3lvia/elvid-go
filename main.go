package main

import (
	"github.com/3lvia/elvid-go/elvidserver"
	"net/http"
)

const jwkURL = `https://elvid.test-elvia.io/.well-known/openid-configuration/jwks`

func main() {
	if err := elvidserver.Init(elvidserver.WithJWKURL(jwkURL), elvidserver.WithScope("hes-extensions.machineaccess")); err != nil {
		panic(err)
	}

	h := elvidserver.Wrap(myHandlerFunc)

	go http.Handle("/", h)

	if err := http.ListenAndServe(":8080", h); err != nil {
		panic(err)
	}
}

func myHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`hello world`))
}
