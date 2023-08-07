package elvid

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/3lvia/elvid-go/internal/tlsclient"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

type ElvID struct {
	client *http.Client

	OIDConfig *OIDConfig
	jwks      *keyfunc.JWKS
}

// New creates a new instance of ElvID, used for eg checking token authenticity.
func New(ctx context.Context, opts ...Option) (*ElvID, error) {
	config := newConfig(opts...)

	client, err := tlsclient.New(config.Cert())
	if err != nil {
		return nil, err
	}

	oidConfig, err := fetchOIDConfig(ctx, client, config.Address()+config.Discovery())
	if err != nil {
		return nil, err
	}

	options := keyfunc.Options{
		Ctx:    ctx,
		Client: client,
		RefreshErrorHandler: func(err error) {
			// todo report errors in chan
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
		// todo whitelist jwk algo
	}

	jwks, err := keyfunc.Get(oidConfig.JsonWebKeySetUri, options)
	if err != nil {
		return nil, errors.Join(err, errors.New("failed to create JWKS from resource at the given URL"))
	}

	return &ElvID{
		client:    client,
		OIDConfig: oidConfig,
		jwks:      jwks,
	}, nil
}

// Shutdown cleans up background resources.
func (elvid *ElvID) Shutdown() {
	elvid.jwks.EndBackground()
}

// AuthorizeRequest takes an incoming request on behalf of the service and extracts the token from the "Authorization" header.
// The token is then checked for authenticity, and then the claims of that token is verified against elvia.StandardClaims.
func (elvid *ElvID) AuthorizeRequest(r *http.Request) error {
	return elvid.AuthorizeRequestWithClaims(r, &StandardClaims{})
}

// AuthorizeRequestWithClaims takes an incoming request on behalf of the service and extracts the token from the "Authorization" header.
// The token is then checked for authenticity, and then the claims of that token is verified against the passed claims' struct.
func (elvid *ElvID) AuthorizeRequestWithClaims(r *http.Request, claims Claims) error {
	jwtB64 := r.Header.Get("Authorization")
	jwtB64 = strings.Replace(jwtB64, "Bearer ", "", 1)

	return elvid.AuthorizeWithClaims(jwtB64, claims)
}

// Authorize parses and checks the authenticity of the passed JSON Web Token (JWT).
// The claims of that token is verified against elvia.StandardClaims.
func (elvid *ElvID) Authorize(jwtB64 string) error {
	return elvid.AuthorizeWithClaims(jwtB64, &StandardClaims{})
}

// AuthorizeWithClaims parses and checks the authenticity of the passed JSON Web Token (JWT).
// The claims of that token is verified against the passed claims' struct.
func (elvid *ElvID) AuthorizeWithClaims(jwtB64 string, claims Claims) error {

	opts := []jwt.ParserOption{
		jwt.WithLeeway(time.Minute * 5),
		jwt.WithIssuer(elvid.OIDConfig.Issuer),
		jwt.WithIssuedAt(),
	}

	token, err := jwt.ParseWithClaims(jwtB64, claims, elvid.jwks.Keyfunc, opts...)
	if err != nil {
		return errors.Join(err, errors.New("failed to parse the JWT"))
	}

	if !token.Valid {
		return errors.New("the token is invalid")
	}

	return nil
}