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

	SaveOAuthSession(ctx context.Context, session *models.OAuthSession) (uuid.UUID, error)
	SaveSessionMetadata(ctx context.Context, session *models.SessionMetadata) (int64, error)
	ActiveSession(ctx context.Context, sessionID string) (*models.UserSession, error)
}

// SessionProvider provides operations with session terminate/get session
type SessionProvider interface {
	UserSessions(
		ctx context.Context,
		userID int64,
	) (session []models.Session, err error)
}
