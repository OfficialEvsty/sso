package interfaces

import (
	"sso/internal/domain/models"
	"time"
)

type TokenProvider1 interface {
	MakeIDToken(claims map[string]interface{}, ttl time.Time) (string, error)
	MakeAccessToken(claims map[string]interface{}, ttl time.Time) (string, error)
	MakeRefreshToken(userID int64, ttl time.Time) (string, error)
	RefreshToken(token string) (*models.RefreshToken, error)
}
