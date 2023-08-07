package cert

import (
	"errors"
	"fmt"
	"os"
)

// AppendFromFiles loads the certs from a slice of filenames to the cert pool
func (pool Pool) AppendFromFiles(certFiles []string) error {
	for _, cert := range certFiles {
		if cert != "" {
			if err := pool.loadFromFile(cert); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadFromFile loads the certs from a specified file to the provided pool
func (pool Pool) loadFromFile(cert string) error {
	pem, err := os.ReadFile(cert)
	if err != nil {
		return errors.Join(err, errors.New(fmt.Sprintf("failed to read CA file \"%s\" from disk", cert)))
	}

	if err := pool.loadFromPEM(pem); err != nil {
		return errors.Join(err, errors.New(fmt.Sprintf("failed to load CA file \"%s\"", cert)))
	}

	return nil
}

// loadCert appends the PEM-formatted certificate to the provided pool
func (pool Pool) loadFromPEM(pem []byte) error {
	if ok := pool.Certs.AppendCertsFromPEM(pem); !ok {
		return errors.New("failed to parse PEM")
	}

	return nil
}