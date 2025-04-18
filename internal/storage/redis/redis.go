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

var (
	InfoCacheDisabled = errors.New("info cache is disabled")
	ErrKeyNotFound    = errors.New("key not found")
	ErrTagNotFound    = errors.New("tag not found")
)

// TaggedProvider is an interface to provide stringing tags operation on cache key
type TaggedProvider interface {
	AddTag(tag string) *Tagged
	Err() error
}

type Tagged struct {
	cache         *CacheWrapper
	key           string
	ctx           context.Context
	previousError error
}

// NewTagged creates an instance of Tagged entity
func NewTagged(cache *CacheWrapper, key string, ctx context.Context, pError error) *Tagged {
	return &Tagged{
		cache:         cache,
		key:           key,
		ctx:           ctx,
		previousError: pError,
	}
}

// AddTag is an implementation of method Tagger's interface AddTag
func (t *Tagged) AddTag(tag string) *Tagged {
	if t.previousError != nil || t.key == "" {
		return t
	}
	t.cache.SAdd(t.ctx, t.key, tag)
	return t
}

func (t *Tagged) Err() error {
	return t.previousError
}

// CacheWrapper custom wrapper
type CacheWrapper struct {
	*redis.Client
	enabled bool
	keysTTL map[string]time.Duration
	timeout time.Duration
}

// Enabled Getter
func (w *CacheWrapper) Enabled() bool {
	return w.enabled
}

// KeyTTL gets duration of key's time to live
func (w *CacheWrapper) KeyTTL(key string) time.Duration {
	ttl, ok := w.keysTTL[key]
	if !ok {
		return w.keysTTL["default"]
	}
	return ttl
}

// Set async writes model's data into cache with ttl and key
// Throws error InfoCacheDisabled if caches disabled,
func (w *CacheWrapper) Set(key string, data interface{}, ttlKey string) TaggedProvider {
	if !w.enabled {
		return NewTagged(w, key, nil, InfoCacheDisabled)
	}
	cacheCtx := context.Background()
	go func() {
		if err := w.Client.Set(cacheCtx, key, data, w.KeyTTL(ttlKey)).Err(); err != nil {
		}
	}()
	return NewTagged(w, key, cacheCtx, nil)
}

// Get receive early written data model from cache by key
// Throws error InfoCacheDisabled if caches disabled,
// Throws error ErrKeyNotFound if specified key not presented in cache
func (w *CacheWrapper) Get(ctx context.Context, key string, dest interface{}) error {
	if !w.enabled {
		return InfoCacheDisabled
	}
	data, err := w.Client.Get(ctx, key).Bytes()
	if err != nil {
		return ErrKeyNotFound
	}

	if err = json.Unmarshal(data, &dest); err != nil {
		return fmt.Errorf("error while unmarshaling json data into struct %s: %w", key, err)
	}
	return nil
}

// Invalidate deletes cache key if src data
// Throws error InfoCacheDisabled if caches disabled,
func (w *CacheWrapper) Invalidate(key string) error {
	if !w.enabled {
		return InfoCacheDisabled
	}
	go func() {
		ctxCache, cancel := context.WithTimeout(context.Background(), w.timeout*time.Second)
		defer cancel()
		if err := w.Client.Del(ctxCache, key).Err(); err != nil {

		}
	}()
	return nil
}

// InvalidateByTag deletes group keys union by specified tag
// Throws error InfoCacheDisabled if caches disabled
func (w *CacheWrapper) InvalidateByTag(tag string) error {
	if !w.enabled {
		return InfoCacheDisabled
	}
	go func() {
		ctxCache, cancel := context.WithTimeout(context.Background(), w.timeout*time.Second)
		defer cancel()
		keys, err := w.Client.SMembers(ctxCache, tag).Result()
		if err != nil {
			return
		}
		if len(keys) == 0 {
			return
		}
		for _, key := range keys {
			if err = w.Client.Del(ctxCache, key).Err(); err != nil {
			}
		}
	}()
	return nil
}

// Cache using redis provides fast access to important and reusing data
type Cache struct {
	rdb                   *CacheWrapper
	sessionTTL            time.Duration
	emailAuthTokenTTL     time.Duration
	passwordResetTokenTTL time.Duration
}

func (c *Cache) GetConnection() *CacheWrapper {
	return c.rdb
}

// NewCache creates new instance of redis client
func NewCache(conf *config.RedisConfig) (*Cache, error) {
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

	return &Cache{rdb: &CacheWrapper{
		Client:  rdb,
		enabled: conf.CacheConfig.Enabled,
		keysTTL: conf.CacheConfig.CacheKeyTTLs,
		timeout: 5 * time.Second,
	},
		sessionTTL:            conf.SessionTTL,
		emailAuthTokenTTL:     conf.EmailAuthTokenTTL,
		passwordResetTokenTTL: conf.PasswordResetTokenTTL,
	}, nil
}

// SaveSession saves user's session in cache
func (c *Cache) SaveSession(
	ctx context.Context,
	userID int64,
	appID int32,
	ip string,
	device string,
) (sessionID string, err error) {
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
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
	if !c.rdb.Enabled() {
		return storage.InfoCacheDisabled
	}
	tokenKey := "mail_auth_token:" + token
	err := c.rdb.Del(ctx, tokenKey).Err()
	if err != nil {
		return err
	}
	return nil
}
