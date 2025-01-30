package cached_postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
	"sso/internal/storage/redis"
	"time"
)

type CachedStorage struct {
	s *postgres.Storage
	c *redis.Cache
}

// NewCachedStorage creates an instance of combined storage with cache
func NewCachedStorage(
	s *postgres.Storage,
	c *redis.Cache,
) *CachedStorage {
	return &CachedStorage{s: s, c: c}
}

// CachedRefreshToken returns token if it stores in cache else use postgres storage to get it
func (cs *CachedStorage) CachedRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	// cache(redis)
	refreshToken, err := cs.c.RefreshToken(ctx, token)
	if err != nil {
		if !errors.Is(err, storage.InfoCacheKeyNotFound) || errors.Is(err, storage.InfoCacheDisabled) {
			return nil, err
		}
	}
	if err == nil {
		return refreshToken, nil
	}
	// postgres
	refreshToken, err = cs.s.RefreshToken(ctx, token)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	return refreshToken, nil
}

// CachedSaveRefreshToken saves token in both cache and db
func (cs *CachedStorage) CachedSaveRefreshToken(
	ctx context.Context,
	tx pgx.Tx,
	userID int64,
	token string,
	expiresAt time.Time,
) error {
	// postgres
	tokenID, err := cs.s.SaveToken(
		ctx,
		tx,
		userID,
		token,
		expiresAt,
	)
	if err != nil {
		return err
	}

	err = cs.c.SaveRefreshToken(
		ctx,
		tokenID,
		userID,
		token,
		expiresAt,
	)
	if err != nil {
		fmt.Println("error save token in cache: " + err.Error())
	}
	return nil
}

// CachedDeleteRefreshToken deletes both storage cache and db
func (cs *CachedStorage) CachedDeleteRefreshToken(ctx context.Context, token string, isRollback bool) (*pgx.Tx, error) {
	err := cs.c.DeleteRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}
	tx, err := cs.s.RemoveToken(ctx, token, isRollback)
	if err != nil {
		return nil, err
	}
	return tx, nil
}
