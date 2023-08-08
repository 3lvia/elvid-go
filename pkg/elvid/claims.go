package elvid

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

const (
	elviaIdp string = "elvia-ad"
)

var (
	ErrInvalidIdp = errors.New("invalid IDP")
)

type Claims interface {
	jwt.Claims
	Validate() error
}

type StandardClaims struct {
	jwt.RegisteredClaims
	Idp        string   `json:"idp,omitempty"`
	Scope      []string `json:"scope,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	ClientName string   `json:"client_name,omitempty"`
}

func (c StandardClaims) Validate() error {
	if c.Idp != elviaIdp {
		return ErrInvalidIdp
	}

	return nil
}