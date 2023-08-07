package tlsclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/3lvia/elvid-go/internal/cert"
)

// New creates a new instance of http.Client that is configured to use tls.VersionTLS12 as minimum
// and a cert.Pool based on Let's Encrypt public root level certificate and the passed in certificates.
func New(certificates ...string) (*http.Client, error) {
	var tlsConfig *tls.Config

	// Skipping TLS verification should only be used for testing
	if strings.ToLower(os.Getenv("INSECURE_SKIP_TLS_VERIFY")) == "true" {
		fmt.Print("WARNING: Using insecure_skip_tls_verify mode! This should only happen during development.\n")
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
	} else {
		pool, err := cert.MakePool(certificates...)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool.Certs,
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	return httpClient, nil
}