package cached

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
	redis2 "sso/internal/storage/redis"
)

// Redis keys
// -- rt: refresh token
const (
	rTokenKey = "rt"
	// tags
	tag = "tag"
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

// RefreshToken receive data models.RefreshToken
// Supports LAZY-LOADING
func (r *TokenCachedRepository) RefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	// try to get data from cache
	cacheKey := fmt.Sprintf("%s:%s", rTokenKey, token)
	var rToken models.RefreshToken
	if err := r.cache.Get(ctx, cacheKey, &rToken); err == nil {
		return &rToken, nil
	}

	// getting data from db
	row := r.db.QueryRow(ctx, "SELECT * FROM refresh_tokens WHERE token = $1", token)
	err := row.Scan(&rToken.ID, &rToken.UserID, &rToken.Token, &rToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrTokenInvalid
		}
		return nil, err
	}

	// write to cache to further getting operations will provide by cache (set async)
	_ = r.cache.Set(cacheKey, rToken, rTokenKey).AddTag(fmt.Sprintf("%s:%d", tag, rToken.UserID)).Err()
	return &rToken, nil
}

// SaveRefreshToken receive data models.RefreshToken
func (r *TokenCachedRepository) SaveRefreshToken(ctx context.Context, tokenToSave *models.RefreshToken) error {
	table := "refresh_tokens"
	conflictedField := "id"
	_, err := r.db.SaveOrUpdate(ctx, table, tokenToSave, conflictedField)
	if err != nil {
		return fmt.Errorf("error while writing refresh token to database: %w", err)
	}
	return nil
}

// RemoveAllUserTokens receive data about models.RefreshToken
func (r *TokenCachedRepository) RemoveAllUserTokens(ctx context.Context, userID int64) error {
	// deleting all rtokens from db
	_, err := r.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("error while deleting all user's refresh tokens: %w", err)
	}

	//invalidating cache by tag specifying user id
	_ = r.cache.InvalidateByTag(fmt.Sprintf("%s:%d", tag, userID))
	return nil
}

// RevokeRefreshToken receive data about models.RefreshToken
func (r *TokenCachedRepository) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	// delete refresh token record from db
	_, err := r.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE token = $1", refreshToken)
	if err != nil {
		return fmt.Errorf("error while deleting refresh token from database: %w", err)
	}

	// invalidates cache key
	cacheKey := fmt.Sprintf("%s:%s", rTokenKey, refreshToken)
	_ = r.cache.Invalidate(cacheKey)
	return nil
}

// UpdateRefreshToken updates refresh token by one transaction
// Transaction method usage to prevent non consistent behaviour
func (r *TokenCachedRepository) UpdateRefreshToken(ctx context.Context, refreshToken *models.RefreshToken) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", refreshToken.UserID)
	if err != nil {
		return fmt.Errorf("error while deleting refresh token from database: %w", err)
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		refreshToken.UserID,
		refreshToken.Token,
		refreshToken.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("error while writing refresh token to database: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	_ = r.cache.InvalidateByTag(fmt.Sprintf("%s:%d", tag, refreshToken.UserID))
	return nil
}
