package elvidtoken

import (
	"io"
	"net/http"
	"strings"
)

// Wrap is the main interface of this package. It wraps an http.HandlerFunc and returns a new http.HandlerFunc that
// validates the bearer token in the Authorization header and checks if the token has the correct scope. If the token is
// invalid, the wrapped http.HandlerFunc is not called and a 401 is returned instead. If the token is valid, the wrapped
// http.HandlerFunc is called with the original http.ResponseWriter and http.Request.
func Wrap(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		if bearerToken == "" {
			w.Write([]byte("missing bearer token"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		arr := strings.Split(bearerToken, " ")
		if len(arr) != 2 {
			w.Write([]byte("malformed bearer token"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		scps, err := parse(arr[1], currentKey)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !scps.hasScope(currentScope) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		f(w, r)
	}
}

func getJWK(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	response, err := currentClient.Do(req)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}
