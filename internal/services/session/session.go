package session

import (
	"context"
	"log/slog"
)

type Session struct {
	log *slog.Logger
	SessionStorage
	SessionProvider
}

// SessionStorage for store sessions
type SessionStorage interface {
	SaveSession(
		ctx context.Context,
		ip string,
		device string,
		expiresAt int64,
	) (sessionID int64, err error)
}

// SessionProvider provides operations with session terminate/get session
type SessionProvider interface {
	UserSessions(
		ctx context.Context,
		userID int64,
	) (session []*Session, err error)
}
