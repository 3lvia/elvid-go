package elvid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type OIDConfig struct {
	Issuer                      string `json:"issuer"`
	JsonWebKeySetUri            string `json:"jwks_uri"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	UserInfoEndpoint            string `json:"userinfo_endpoint"`
	EndSessionEndpoint          string `json:"end_session_endpoint"`
	CheckSessionEndpoint        string `json:"check_session_iframe"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
	IntrospectionEndpoint       string `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

func fetchOIDConfig(ctx context.Context, client *http.Client, url string) (*OIDConfig, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config OIDConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, errors.Join(err, errors.New("failed to read body"))
	}
	return &config, nil
}