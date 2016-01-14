package auth

import (
	"errors"
)

var (
	ErrUserIdInvalid           = errors.New("User id must be 5 - 32 letters,digits or _")
	ErrUserIdForbidden         = errors.New("User id is not allowed")
	ErrWrongUsernameOrPassword = errors.New("Username or password incorrect")
	ErrWrongRefreshToken       = errors.New("Refresh token incorrect")
)

var (
	ErrNotFound   = errors.New("No record found")
	ErrUserExists = errors.New("User Id exists")
)

var userErrors = map[error]bool{
	ErrUserIdInvalid:           true,
	ErrUserIdForbidden:         true,
	ErrWrongUsernameOrPassword: true,
	ErrUserExists:              true,
}

func IsUserError(err error) bool {
	_, present := userErrors[err]
	return present
}
