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

func New(ctx context.Context, opts ...Option) (*ElvID, error) {
	config := NewConfig(opts...)

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
	// todo return shutdown func
	// defer jwks.EndBackground()

	return &ElvID{
		client:    client,
		OIDConfig: oidConfig,
		jwks:      jwks,
	}, nil
}

func (elvid *ElvID) AuthorizeRequest(r *http.Request) error {
	return elvid.AuthorizeRequestWithClaims(r, &StandardClaims{})
}

func (elvid *ElvID) AuthorizeRequestWithClaims(r *http.Request, claims Claims) error {
	jwtB64 := r.Header.Get("Authorization")
	jwtB64 = strings.Replace(jwtB64, "Bearer ", "", 1)

	return elvid.AuthorizeWithClaims(jwtB64, claims)
}

func (elvid *ElvID) Authorize(jwtB64 string) error {
	return elvid.AuthorizeWithClaims(jwtB64, &StandardClaims{})
}

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