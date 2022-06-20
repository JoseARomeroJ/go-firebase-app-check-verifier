package app_check_verifier

import (
	"net/http"
)

func (v verifier) AppCheckVerifier(next http.Handler) http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := GetTokenFromRequest(r); token == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if err := v.VerifyToken(*token); err != nil && err == ErrInvalidToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})

	return h
}
