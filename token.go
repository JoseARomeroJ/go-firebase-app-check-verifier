package appchecker

import "net/http"

func GetTokenFromRequest(r *http.Request) *string {
	if r == nil {
		return nil
	}

	token := r.Header.Get(tokenHeader)
	if token == "" {
		return nil
	}

	return &token
}
