package models

import "time"

// Refresh token's model
type RefreshToken struct {
	ID        int64     `json:"id,string" db:"id"`
	Token     string    `json:"refresh_token"`
	UserID    int64     `json:"user_id,string" db:"user_id"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
}
