package appchecker

import "errors"

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrCannotFetchJWTKeys = errors.New("cannot get the jwt keys")
	ErrInvalidKeys        = errors.New("invalid jwt keys")
)
