package auth

import (
	"errors"
)

var ErrUserIdInvalid = errors.New("User id must be 5 - 32 letters,digits or _")
var ErrUserIdForbidden = errors.New("User id is not allowed")
var ErrWrongUsernameOrPassword = errors.New("Username or password incorrect")
var ErrWrongRefreshToken = errors.New("Refresh token incorrect")

var (
	ErrNotFound   = errors.New("No record found")
	ErrUserExists = errors.New("User Id exists")
)
