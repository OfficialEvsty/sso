package interfaces

import (
	"context"
	"github.com/jackc/pgx/v5"
	"sso/internal/domain/models"
	"time"
)

type UserStorage interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	UserById(ctx context.Context, id int64) (models.User, error)
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, uid int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (app models.App, err error)
}

// TokenCleaner interface for delete refresh tokens
type TokenCleaner interface {
	RemoveAllUserTokens(ctx context.Context, userID int64) error
}

// TokenProvider interface for save/get refresh tokens
type TokenProvider interface {
	CachedRefreshToken(ctx context.Context, token string) (refreshToken *models.RefreshToken, err error)
	CachedSaveRefreshToken(ctx context.Context, tx pgx.Tx, userID int64, token string, expiresAt time.Time) error
	CachedDeleteRefreshToken(ctx context.Context, token string, isRollback bool) (*pgx.Tx, error)
}
