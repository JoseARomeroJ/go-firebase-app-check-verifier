package app_check_verifier

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"strings"
	"time"
)

type Verifier interface {
	VerifyToken(token string) error

	AppCheckVerifier(next http.Handler) http.Handler
}

type verifier struct {
	projectName        string
	projectAppCheckUrl string
	projectPath        string

	keysRefresher keyfunc.Options
}

func New(projectName string) Verifier {
	v := verifier{
		projectName:        projectName,
		projectAppCheckUrl: fmt.Sprintf(appProjectUrl, projectName),
		projectPath:        fmt.Sprintf(appProjectPath, projectName),
	}

	v.keysRefresher = keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			log.Printf("there was an error with refreshing the keys")
		},
		RefreshInterval: time.Hour * 5,
	}

	return v
}

func (v verifier) VerifyToken(token string) error {
	if token == "" {
		return ErrInvalidToken
	}

	keys, err := keyfunc.Get(appCheckPublicKeysEndpoint, v.keysRefresher)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrCannotFetchJWTKeys, err)
	}

	payload, err := jwt.Parse(token, keys.Keyfunc)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidKeys, err)
	}

	err = v.validateResponse(payload)
	if err != nil {
		return err
	}

	return nil
}

func (v verifier) validateResponse(r *jwt.Token) error {
	if !r.Valid {
		return ErrInvalidToken
	} else if r.Header["alg"] != "RS256" {
		return ErrInvalidToken
	} else if r.Header["typ"] != "JWT" {
		return ErrInvalidToken
	} else if !v.verifyAudience(r.Claims.(jwt.MapClaims)["aud"].([]interface{})) {
		return ErrInvalidToken
	} else if !strings.Contains(r.Claims.(jwt.MapClaims)["iss"].(string), v.projectAppCheckUrl) {
		return ErrInvalidToken
	}

	return nil
}

func (v verifier) verifyAudience(audiences []interface{}) bool {
	for _, aud := range audiences {
		if aud == v.projectPath {
			return true
		}
	}
	return false
}
