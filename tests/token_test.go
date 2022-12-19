package tests

import (
	"github.com/3lvia/elvid-go/elvidtoken"
	"testing"
)

const jwkURL = `https://elvid.test-elvia.io/.well-known/openid-configuration/jwks`

func Test_token(t *testing.T) {
	err := token.Init(token.WithJWKURL(jwkURL))
	if err != nil {
		t.Errorf("token.Init() error = %v", err)
	}
}
