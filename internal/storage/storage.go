package storage

import "errors"

var (
	ErrUserExists     = errors.New("user already exists")
	ErrUserNotFound   = errors.New("user not found")
	ErrAppNotFound    = errors.New("app not found")
	ErrUserNotExist   = errors.New("user not exists")
	ErrTokenInvalid   = errors.New("token is invalid")
	ErrTokenExpired   = errors.New("token is expired")
	ErrKeyNotFound    = errors.New("redis key not found")
	ErrRoleNotFound   = errors.New("role not found")
	InfoCacheDisabled = errors.New("info cache is disabled")
)
