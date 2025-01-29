package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"sso/internal/config"
	"sso/internal/domain/models"
	"sso/internal/lib/extensions"
	"sso/internal/storage"
	"strconv"
	"time"
)

// Cache using redis provides fast access to important and reusing data
type Cache struct {
	rdb        *redis.Client
	sessionTTL time.Duration
	useCache   bool
}

// NewCache creates new instance of redis client
func NewCache(conf *config.RedisConfig, useCache bool) (*Cache, error) {
	get := extensions.GetEnv

	host, port, password :=
		get("REDIS_HOST", "localhost"),
		get("REDIS_PORT", "6379"),
		get("REDIS_PASSWORD", "")

	rdb := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password,
		DB:       0,
	})

	return &Cache{rdb: rdb, sessionTTL: conf.SessionTTL, useCache: useCache}, nil
}

// SaveSession saves user's session in cache
func (c *Cache) SaveSession(
	ctx context.Context,
	userID int64,
	appID int32,
	ip string,
	device string,
) (sessionID string, err error) {
	if !c.useCache {
		return "", storage.InfoCacheDisabled
	}
	sessionID = "session:" + strconv.Itoa(int(userID))
	sessionData, err := json.Marshal(models.Session{
		UserID:    strconv.Itoa(int(userID)),
		AppID:     strconv.Itoa(int(appID)),
		Ip:        ip,
		Device:    device,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}

	err = c.rdb.HSet(
		ctx,
		sessionID,
		appID,
		sessionData,
	).Err()
	if err != nil {
		return "", errors.New("failed to save session: " + err.Error())
	}

	err = c.rdb.Expire(ctx, sessionID, c.sessionTTL).Err()
	if err != nil {
		return "", errors.New("failed to set session TTL: " + err.Error())
	}
	return sessionID, nil
}

// UserSessions gets all sessions of specified user in all bounded applications
func (c *Cache) UserSessions(
	ctx context.Context,
	userID int64,
) ([]models.Session, error) {
	if !c.useCache {
		return nil, storage.InfoCacheDisabled
	}
	key := "session:" + strconv.Itoa(int(userID))
	result, err := c.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var sessions []models.Session
	var session models.Session
	for _, val := range result {
		fmt.Println(val)
		err = json.Unmarshal([]byte(val), &session)
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil, err
			}
			return nil, errors.New("error parsing json data: " + err.Error())
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}
