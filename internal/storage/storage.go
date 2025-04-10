package storage

import "errors"

var (
	ErrUserExists              = errors.New("user already exists")
	ErrUserNotFound            = errors.New("user not found")
	ErrAppNotFound             = errors.New("app not found")
	ErrUserNotExist            = errors.New("user not exists")
	ErrTokenInvalid            = errors.New("token is invalid")
	ErrTokenExpired            = errors.New("token is expired")
	ErrKeyNotFound             = errors.New("redis key not found")
	ErrRoleNotFound            = errors.New("role not found")
	ErrPermissionDenied        = errors.New("you has no permissions for this action")
	ErrUserNotConfirmedEmail   = errors.New("user not confirmed email")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrNoMetadataContext       = errors.New("no metadata context provided")
	InfoCacheDisabled          = errors.New("info cache is disabled")
	InfoCacheKeyNotFound       = errors.New("cache key not found")
	InfoUserAlreadyHasRole     = errors.New("user already has role")
	InfoUserHasNoSpecifiedRole = errors.New("user has no specified role")
	InfoSessionsDisabled       = errors.New("sessions is disabled")
	InfoUserUnauthenticated    = errors.New("user session not found")
	InfoSessionExpired         = errors.New("session is expired")
	InfoIPChanged              = errors.New("ipv4 address is changed")
	InfoTrustedIPNotFound      = errors.New("trusted IP not found")
)
