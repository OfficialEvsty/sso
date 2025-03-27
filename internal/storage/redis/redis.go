package redis

import (
	"context"
	"encoding/json"
	"errors"
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
	rdb                   *redis.Client
	sessionTTL            time.Duration
	emailAuthTokenTTL     time.Duration
	passwordResetTokenTTL time.Duration
	useCache              bool
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

	return &Cache{rdb: rdb, sessionTTL: conf.SessionTTL,
		emailAuthTokenTTL:     conf.EmailAuthTokenTTL,
		passwordResetTokenTTL: conf.PasswordResetTokenTTL,
		useCache:              useCache}, nil
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

// SaveRefreshToken saves token in cache
func (c *Cache) SaveRefreshToken(
	ctx context.Context,
	id int64,
	userID int64,
	token string,
	expiresAt time.Time,
) error {
	if !c.useCache {
		return storage.InfoCacheDisabled
	}
	tokenKey := "refresh_tokens:" + token
	tokenData := map[string]interface{}{
		"id":         id,
		"user_id":    userID,
		"token":      token,
		"expires_at": expiresAt,
	}
	err := c.rdb.HSet(ctx, tokenKey, tokenData).Err()
	if err != nil {
		return err
	}
	err = c.rdb.Expire(ctx, tokenKey, c.sessionTTL).Err()
	if err != nil {
		return err
	}
	return nil
}

// допустил глупую ощибку в имя ключа поставил -, а не _ и тупил 30 минут, нормализируйте имена ключей
// RefreshToken gets token from cache if it
func (c *Cache) RefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	if !c.useCache {
		return nil, storage.InfoCacheDisabled
	}
	tokenKey := "refresh_tokens:" + token
	cachedString, err := c.rdb.HGetAll(ctx, tokenKey).Result()
	if err != nil {
		return nil, err
	}
	if len(cachedString) == 0 {
		return nil, storage.InfoCacheKeyNotFound
	}
	var cashedToken models.RefreshToken
	jsonData, err := json.Marshal(cachedString)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &cashedToken)
	if err != nil {
		return nil, err
	}
	return &cashedToken, nil
}

// DeleteRefreshToken removes token from cache
func (c *Cache) DeleteRefreshToken(ctx context.Context, token string) error {
	if !c.useCache {
		return storage.InfoCacheDisabled
	}
	tokenKey := "refresh_tokens:" + token
	err := c.rdb.Del(ctx, tokenKey).Err()
	if err != nil {
		return err
	}
	return nil
}

// SaveEmailToken saves token for mail authorization due to check user's email valid
// If useCache disabled throws error
func (c *Cache) SaveEmailToken(ctx context.Context, email string, token string) error {
	if !c.useCache {
		return storage.InfoCacheDisabled
	}
	tokenKey := "mail_auth_token:" + token
	tokenExpiresAt := time.Now().Add(c.emailAuthTokenTTL)
	tokenData := map[string]interface{}{
		"email":     email,
		"expiresAt": tokenExpiresAt,
	}
	err := c.rdb.HSet(ctx, tokenKey, tokenData).Err()
	if err != nil {
		return err
	}
	err = c.rdb.Expire(ctx, tokenKey, c.emailAuthTokenTTL).Err()
	if err != nil {
		return err
	}
	return nil
}

// EmailToken gets cached token, if it not expires and verify email attached to user
func (c *Cache) EmailToken(ctx context.Context, token string) (*models.MailAuthToken, error) {
	if !c.useCache {
		return nil, storage.InfoCacheDisabled
	}
	tokenKey := "mail_auth_token:" + token
	cachedString, err := c.rdb.HGetAll(ctx, tokenKey).Result()
	if err != nil {
		return nil, err
	}
	if len(cachedString) == 0 {
		return nil, storage.InfoCacheKeyNotFound
	}
	var cachedToken models.MailAuthToken
	jsonData, err := json.Marshal(cachedString)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(jsonData), &cachedToken)
	if err != nil {
		return nil, err
	}
	return &cachedToken, nil
}

// DeleteEmailToken removes token from cache
func (c *Cache) DeleteEmailToken(ctx context.Context, token string) error {
	if !c.useCache {
		return storage.InfoCacheDisabled
	}
	tokenKey := "mail_auth_token:" + token
	err := c.rdb.Del(ctx, tokenKey).Err()
	if err != nil {
		return err
	}
	return nil
}
