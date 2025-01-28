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
		userID int64,
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

func (s *Session) SaveUserSession(
	ctx context.Context,
	ip string,
	userID int64,
	device string,
	expiresAt int64,
) (sessionID int64, err error) {
	const op = "session.SaveUserSession"

}
