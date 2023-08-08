package elvid

import (
	"testing"

	"github.com/3lvia/elvid-go/testing/assert"
	"github.com/golang-jwt/jwt/v5"
)

var (
	validClaims = StandardClaims{
		RegisteredClaims: jwt.RegisteredClaims{},
		Idp:              elviaIdp,
		Scope: []string{
			"openid",
		},
		ClientID:   "123456",
		ClientName: "test",
	}

	invalidClaims = StandardClaims{
		RegisteredClaims: jwt.RegisteredClaims{},
		Idp:              "not-valid",
		Scope:            nil,
		ClientID:         "",
		ClientName:       "",
	}
)

func TestStandardClaims_Validate(t *testing.T) {
	tt := []struct {
		test    string
		wantErr error
		claims  StandardClaims
	}{
		{
			test:    "invalid idp",
			wantErr: ErrInvalidIdp,
			claims:  invalidClaims,
		},
		{
			test:    "valid claims",
			wantErr: nil,
			claims:  validClaims,
		},
	}

	for i := range tt {
		tc := tt[i]

		t.Run(tc.test, func(t *testing.T) {
			t.Parallel()

			gotErr := tc.claims.Validate()

			assert.Err(t, gotErr, tc.wantErr)
		})
	}
}