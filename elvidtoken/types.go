package elvidtoken

import "github.com/golang-jwt/jwt/v4"

type scopes interface {
	hasScope(scope string) bool
}

func claimsAndScopes(c jwt.MapClaims) scopes {
	return &scopesImpl{mc: c}
}

type scopesImpl struct {
	mc jwt.MapClaims
}

func (c scopesImpl) hasScope(scope string) bool {
	scopes := c.mc["scope"]
	for _, s := range scopes.([]interface{}) {
		if s == scope {
			return true
		}
	}

	return false
}

func (c scopesImpl) ClientID() string {
	//TODO implement me
	panic("implement me")
}

func (c scopesImpl) ClientName() string {
	//TODO implement me
	panic("implement me")
}
