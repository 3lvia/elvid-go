package elvid

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrEmptyClientID = errors.New("the clientid is empty")
)

type Claims interface {
	jwt.Claims
	Validate() error
}

type StandardClaims struct {
	jwt.RegisteredClaims
	Scope      []string `json:"scope,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	ClientName string   `json:"client_name,omitempty"`
}

func (c StandardClaims) Validate() error {
	if c.ClientID == "" {
		return ErrEmptyClientID
	}

	return nil
}