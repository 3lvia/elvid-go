package tlsclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/3lvia/elvid-go/internal/cert"
)

func New(certificates ...string) (*http.Client, error) {
	var tlsConfig *tls.Config

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