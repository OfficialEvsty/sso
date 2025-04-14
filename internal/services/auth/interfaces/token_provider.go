package interfaces

import (
	"context"
	"sso/internal/domain/models"
	"time"
)

// TokenProvider generates JWT
type TokenProvider interface {
	MakeIDToken(claims map[string]interface{}, ttl time.Time) (string, error)
	MakeAccessToken(claims map[string]interface{}, ttl time.Time) (string, error)
	MakeRefreshToken(userID int64, ttl time.Time) (string, error)
}

// TokenStorage perform db operations
type TokenStorage interface {
	RefreshToken(token string) (*models.RefreshToken, error)
	SaveRefreshToken(context.Context, *models.RefreshToken) error
	RemoveAllUserTokens(ctx context.Context, userID int64) error
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
}
