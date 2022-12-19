package elvidserver

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

func parseJWK(b []byte) (*rsa.PublicKey, error) {
	set, err := jwk.Parse(b)
	if err != nil {
		return nil, err
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawKey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err = key.Raw(&rawKey); err != nil {
			return nil, err
		}

		// We know this is an RSA Key so...
		rsa, ok := rawKey.(*rsa.PublicKey)
		if !ok {
			return nil, err
		}

		return rsa, nil
	}

	return nil, errors.New("no key found")
}

func parse(tokenString string, key *rsa.PublicKey) (scopes, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return key, nil
	}

	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(tokenString, keyFunc)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		mc := claimsAndScopes(claims)
		return mc, nil
	}

	return nil, err
}
