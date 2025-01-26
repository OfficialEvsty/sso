package models

// Refresh token's model
type RefreshToken struct {
	ID        int64  `json:"id" db:"id"`
	Token     string `json:"refresh_token"`
	UserID    int64  `json:"user_id" db:"user_id"`
	ExpiresAt int64  `json:"expires_at" db:"expires_at"`
	CreatedAt int64  `json:"created_at" db:"created_at"`
}
