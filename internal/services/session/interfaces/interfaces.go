package interfaces

import (
	"context"
	"sso/internal/domain/models"
)

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
