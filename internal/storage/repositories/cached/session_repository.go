package cached

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"sso/internal/domain/models"
	"sso/internal/storage"
	"sso/internal/storage/postgres"
	redis2 "sso/internal/storage/redis"
)

// Redis keys
// -- s: Session
// -- us: User Session (Active session)
// -- sm: Session's metadata
const (
	sessionKey     = "s"
	userSessionKey = "us"
	//sessionMetadataKey = "sm"
)

// SessionCachedRepository cached repository allows gets/sets sessions
type SessionCachedRepository struct {
	db    *postgres.ExtPool
	cache *redis2.CacheWrapper
}

// NewSessionCachedRepository creates an instance of SessionCachedRepository
func NewSessionCachedRepository(db *postgres.ExtPool, cache *redis2.CacheWrapper) *SessionCachedRepository {
	return &SessionCachedRepository{
		db:    db,
		cache: cache,
	}
}

// Session gets unauthenticated session models.OAuthSession from db
// LazyLoading support
func (r *SessionCachedRepository) Session(ctx context.Context, sessionID string) (*models.OAuthSession, error) {
	// try to get session from cache
	var session models.OAuthSession
	cacheKey := fmt.Sprintf("%s:%s", sessionKey, sessionID)
	if err := r.cache.Get(ctx, cacheKey, &session); err == nil {
		return &session, nil
	}
	err := r.db.QueryRow(
		ctx,
		`SELECT id, client_id, ipv4, scope, created_at, expires_at FROM sessions WHERE id = $1`,
		sessionID,
	).Scan(&session.Id, &session.ClientId, &session.Ip, &session.Scope, &session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("error while getting session: %w", err)
		}
		return nil, storage.InfoSessionNotFound
	}

	// write to cache to further getting operations will provide by cache (set async)
	err = r.cache.Set(cacheKey, session, sessionKey).AddTag(fmt.Sprintf("%s:%s", tag, session.Ip.String())).Err()
	return &session, nil
}

// SessionMetadata gets models.SessionMetadata, which stores in db related to models.OAuthSession by sessionID key
func (r *SessionCachedRepository) SessionMetadata(ctx context.Context, sessionID string) (*models.SessionMetadata, error) {
	var metadata models.SessionMetadata
	err := r.db.QueryRow(
		ctx,
		`SELECT * FROM session_metadata WHERE session_id = $1`,
		sessionID,
	).Scan(&metadata.Id, &metadata.RedirectUri, &metadata.State, &metadata.SessionID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("error while getting session: %w", err)
		}
		return nil, fmt.Errorf("session's metadata not found: %w", err)
	}
	return &metadata, nil
}

// ActiveSession gets active user's session
func (r *SessionCachedRepository) ActiveSession(ctx context.Context, sessionID string) (*models.UserSession, error) {
	var userSession models.UserSession
	// firstly trying to get from cache
	cacheKey := fmt.Sprintf("%s:%s", userSessionKey, sessionID)
	if err := r.cache.Get(ctx, cacheKey, &userSession); err == nil {
		return &userSession, nil
	}

	row := r.db.QueryRow(
		ctx,
		`SELECT us.id, us.user_id, s.id, s.client_id, s.ipv4, s.scope, s.created_at, s.expires_at FROM user_sessions AS us 
		JOIN sessions AS s ON us.session_id = s.id 
		WHERE s.id = $1`,
		sessionID,
	)
	err := row.Scan(
		&userSession.Id,
		&userSession.UserId,
		&userSession.Session.Id,
		&userSession.Session.ClientId,
		&userSession.Session.Ip,
		&userSession.Session.Scope,
		&userSession.Session.CreatedAt,
		&userSession.Session.ExpiresAt,
	)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, pgx.ErrNoRows
	}

	// write to cache to further getting operations will provide by cache (set async)
	_ = r.cache.Set(cacheKey, userSession, userSessionKey).AddTag(fmt.Sprintf("%s:%d", tag, userSession.UserId)).Err()

	return &userSession, nil
}

// AuthenticateUserSession authenticate models.OAuthSession when user successfully logged in
func (r *SessionCachedRepository) AuthenticateUserSession(ctx context.Context, sessionID string, userID int64) error {
	var id int
	err := r.db.QueryRow(
		ctx,
		`INSERT INTO user_sessions (user_id, session_id) VALUES ($1, $2) RETURNING id`,
		userID,
		sessionID,
	).Scan(&id)
	if err != nil {
		return fmt.Errorf("error while inserting user session: %w", err)
	}
	return nil
}

// SaveOAuthSession saves unauthenticated(empty) models.OAuthSession
func (r *SessionCachedRepository) SaveOAuthSession(ctx context.Context, session *models.OAuthSession) (uuid.UUID, error) {
	table := "sessions"
	sessionID, err := r.db.SaveOrUpdate(ctx, table, session, "id")
	if err != nil {
		return uuid.Nil, err
	}
	uid, err := uuid.Parse(sessionID.(string))
	if err != nil {
		return uuid.Nil, err
	}

	// important: invalidate updated session if exist
	cacheKey := fmt.Sprintf("%s:%s", sessionKey, sessionID)
	_ = r.cache.Invalidate(cacheKey)
	return uid, nil
}

// SaveSessionMetadata saves additional data about models.OAuthSession
func (r *SessionCachedRepository) SaveSessionMetadata(ctx context.Context, sm *models.SessionMetadata) (int64, error) {
	row := r.db.QueryRow(
		ctx,
		`INSERT INTO session_metadata(uri, state, session_id) VALUES($1,$2,$3) RETURNING id`,
		sm.RedirectUri,
		sm.State,
		sm.SessionID,
	)
	var id int64
	err := row.Scan(&id)
	if err != nil {
		var pgxError *pgconn.PgError
		if errors.As(err, &pgxError) {
			if pgxError.Code == "23505" {
				return 0, errors.New("session metadata already exists")
			}
		}
		return 0, err
	}
	return id, nil
}

// RemoveSession removes models.OAuthSession from db
func (r *SessionCachedRepository) RemoveSession(ctx context.Context, sessionID string) error {
	var id string
	err := r.db.QueryRow(
		ctx,
		`DELETE FROM sessions WHERE id = $1`,
		sessionID,
	).Scan(&id)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}

	// important: invalidate cached session
	cacheKey := fmt.Sprintf("%s:%s", sessionKey, sessionID)
	_ = r.cache.Invalidate(cacheKey)
	return nil
}

// RemoveAllUserSessionsExceptCurrent clears all sessions bound to userId except current session
func (r *SessionCachedRepository) RemoveAllUserSessionsExceptCurrent(ctx context.Context, userID int64, sessionID string) error {
	_, err := r.db.Exec(
		ctx,
		`DELETE FROM sessions WHERE id IN (SELECT session_id FROM user_sessions WHERE user_id = $1 AND session_id <> $2)`,
		userID,
		sessionID,
	)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("error while deleting already exists user's sessions: %w", err)
		}
	}

	// important: make delete by tag from cache
	tagUserID := fmt.Sprintf("%s:%d", tag, userID)
	_ = r.cache.InvalidateByTag(tagUserID)
	return nil
}

// RemoveSessionMetadata clears metadata after end of token exchanging
func (r *SessionCachedRepository) RemoveSessionMetadata(ctx context.Context, sessionID string) error {
	_, err := r.db.Exec(
		ctx,
		`DELETE FROM session_metadata WHERE session_id = $1`,
		sessionID,
	)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("error while deleting already exists user's sessions: %w", err)
		}
	}
	return nil
}
