package redis

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"sso/internal/config"
	"strconv"
	"time"
)

// Cache using redis provides fast access to important and reusing data
type Cache struct {
	rdb        *redis.Client
	sessionTTL time.Duration
}

// NewCache creates new instance of redis client
func NewCache(conf *config.RedisConfig) (*Cache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     conf.Host + ":" + strconv.Itoa(conf.Port),
		Password: conf.Password,
		DB:       conf.DB,
	})

	return &Cache{rdb: rdb, sessionTTL: conf.SessionTTL}, nil
}

// SaveSession saves user's session in cache
func (c *Cache) SaveSession(
	ctx context.Context,
	ip string,
	userID int64,
	device string,
	expiresAt time.Time,
) (sessionID uuid.UUID, err error) {
	sessionID = uuid.New()
	sessionData := map[string]interface{}{
		"user_id":    userID,
		"ip":         ip,
		"device":     device,
		"expires_at": expiresAt,
	}
	err = c.rdb.HSet(
		ctx,
		sessionID.String(),
		sessionData,
	).Err()
	if err != nil {
		return uuid.UUID{}, errors.New("failed to save session: " + err.Error())
	}

	err = c.rdb.Expire(ctx, sessionID.String(), c.sessionTTL).Err()
	if err != nil {
		return uuid.UUID{}, errors.New("failed to set session TTL: " + err.Error())
	}

	err = c.rdb.Set(ctx, interface{}(userID), sessionData, c.sessionTTL).Err()
}
