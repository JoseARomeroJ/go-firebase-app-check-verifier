package appchecker

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
	projectsNum         []string
	projectsAppCheckUrl map[string]string
	projectsPath        map[string]string

	keysRefresher keyfunc.Options
}

func New(projectsNum []string) Verifier {
	v := verifier{
		projectsNum:         projectsNum,
		projectsAppCheckUrl: map[string]string{},
		projectsPath:        map[string]string{},
	}

	for _, s := range projectsNum {
		v.projectsAppCheckUrl[s] = fmt.Sprintf(appProjectUrl, s)
		v.projectsPath[fmt.Sprintf(appProjectPath, s)] = s
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
	if err != nil && err == jwt.ErrTokenExpired {
		return fmt.Errorf("%w: %s", ErrInvalidToken, err)
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
	}

	for _, s := range v.projectsAppCheckUrl {
		if strings.Contains(r.Claims.(jwt.MapClaims)["iss"].(string), s) {
			return nil
		}
	}

	return ErrInvalidToken
}

func (v verifier) verifyAudience(audiences []interface{}) bool {
	for _, aud := range audiences {
		if _, ok := v.projectsPath[aud.(string)]; ok {
			return true
		}
	}
	return false
}
