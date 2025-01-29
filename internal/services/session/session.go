package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/storage"
)

type Session struct {
	log             *slog.Logger
	sessionStorage  SessionStorage
	sessionProvider SessionProvider
	Enabled         bool
}

// SessionStorage for store sessions
type SessionStorage interface {
	SaveSession(
		ctx context.Context,
		userID int64,
		appID int32,
		ip string,
		device string,
	) (sessionID string, err error)
}

// SessionProvider provides operations with session terminate/get session
type SessionProvider interface {
	UserSessions(
		ctx context.Context,
		userID int64,
	) (session []models.Session, err error)
}

func New(log *slog.Logger, sessionStorage SessionStorage, sessionProvider SessionProvider, enabled bool) *Session {
	return &Session{
		log:             log,
		sessionStorage:  sessionStorage,
		sessionProvider: sessionProvider,
		Enabled:         enabled,
	}
}

// SaveUserSession saves user's session
// Throws error if cache disabled
func (s *Session) SaveUserSession(
	ctx context.Context,
	ip string,
	userID int64,
	appID int32,
	device string,
) (sessionID string, err error) {
	const op = "session.SaveUserSession"

	sessionID, err = s.sessionStorage.SaveSession(
		ctx,
		userID,
		appID,
		ip,
		device,
	)
	if err != nil {
		if !(errors.Is(err, storage.InfoCacheDisabled)) {
			return "", fmt.Errorf("%s: %w", op, err)
		}
		s.log.Warn("session was not saved, cache disabled", op, sessionID)
		return "", fmt.Errorf("%s: %w", op, err)
	}
	s.log.Info("session successfully saved", op, sessionID)

	return sessionID, nil
}

// GetUserSessions return list of active user's sessions
// Throws err if cache disabled
func (s *Session) GetUserSessions(
	ctx context.Context,
	userID int64) ([]models.Session, error) {
	const op = "session.UserSessions"
	sessions, err := s.sessionProvider.UserSessions(ctx, userID)
	if err != nil {
		if !(errors.Is(err, storage.InfoCacheDisabled)) {
			s.log.Error("failed to retrieve sessions", slog.String("error", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		s.log.Warn("session was not retrieved, cache disabled", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return sessions, nil
}
