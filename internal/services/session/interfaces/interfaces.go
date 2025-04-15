package interfaces

import (
	"context"
	"github.com/google/uuid"
	"sso/internal/domain/models"
)

// SessionStorage for store sessions
type SessionStorage interface {
	//SaveSession(
	//	ctx context.Context,
	//	userID int64,
	//	appID int32,
	//	ip string,
	//	device string,
	//) (sessionID string, err error)

	AuthenticateUserSession(ctx context.Context, sessionID string, userID int64) error
	SaveOAuthSession(ctx context.Context, session *models.OAuthSession) (uuid.UUID, error)
	SessionMetadata(ctx context.Context, sessionID string) (*models.SessionMetadata, error)
	SaveSessionMetadata(ctx context.Context, session *models.SessionMetadata) (int64, error)
	ActiveSession(ctx context.Context, sessionID string) (*models.UserSession, error)
	Session(ctx context.Context, sessionID string) (*models.OAuthSession, error)
	RemoveSession(ctx context.Context, sessionID string) error
	RemoveAllUserSessions(ctx context.Context, userID int64)
}

// SessionProvider provides operations with session terminate/get session
type SessionProvider interface {
	UserSessions(
		ctx context.Context,
		userID int64,
	) (session []models.Session, err error)
}
