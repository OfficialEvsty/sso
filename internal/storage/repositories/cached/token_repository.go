package cached

import (
	"context"
	"sso/internal/domain/models"
	"sso/internal/storage/postgres"
	redis2 "sso/internal/storage/redis"
)

// TokenCachedRepository cached repository allows gets/sets sessions
type TokenCachedRepository struct {
	db    *postgres.ExtPool
	cache *redis2.CacheWrapper
}

// NewTokenCachedRepository creates an instance of TokenCachedRepository
func NewTokenCachedRepository(db *postgres.ExtPool, cache *redis2.CacheWrapper) *TokenCachedRepository {
	return &TokenCachedRepository{
		db:    db,
		cache: cache,
	}
}

// RefreshToken receive data about models.RefreshToken
// Currently unimplemented
// todo implement
func (r *TokenCachedRepository) RefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	return nil, nil
}

// SaveRefreshToken receive data about models.RefreshToken
// Currently unimplemented
// todo implement
func (r *TokenCachedRepository) SaveRefreshToken(context.Context, *models.RefreshToken) error {
	return nil
}

// RemoveAllUserTokens receive data about models.RefreshToken
// Currently unimplemented
// todo implement
func (r *TokenCachedRepository) RemoveAllUserTokens(ctx context.Context, userID int64) error {
	return nil
}

// RevokeRefreshToken receive data about models.RefreshToken
// Currently unimplemented
// todo implement
func (r *TokenCachedRepository) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	return nil
}
