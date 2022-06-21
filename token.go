package appchecker

import "net/http"

func GetTokenFromRequest(r *http.Request) *string {
	if r == nil {
		return nil
	}

	token := r.Header.Get(tokenHeader)
	urlToken := r.URL.Query().Get(tokenHeader)

	if token != "" {
		return &token
	} else if urlToken != "" {
		return &urlToken
	}

	return nil
}
