package models

import (
	uu "github.com/google/uuid"
	"time"
)

// AuthorizationCode model depends on RFC OAUTH2.1
type AuthorizationCode struct {
	Code      uu.UUID   `json:"code" db:"code"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Scope     string    `json:"scope" db:"scope"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}
