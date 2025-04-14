package interfaces

import (
	"context"
	"sso/internal/domain/models"
)

type AuthServiceDependencies interface {
	UserStorage() UserStorage
	UserProvider() UserProvider
	AppProvider() AppProvider
}

type UserStorage interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
	DeleteUser(ctx context.Context, uid int64) (err error)
}

type UserProvider interface {
	UserById(ctx context.Context, id int64) (models.User, error)
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, uid int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (app models.App, err error)
}

// TokenProvider interface for save/get refresh tokens
//type TokenProvider interface {
//	CachedRefreshToken(ctx context.Context, token string) (refreshToken *models.RefreshToken, err error)
//	CachedSaveRefreshToken(ctx context.Context, tx pgx.Tx, userID int64, token string, expiresAt time.Time) error
//	CachedDeleteRefreshToken(ctx context.Context, token string, isRollback bool) (*pgx.Tx, error)
//}

// AuthRequestValidator validates request's args in auth service
// Designed for validation purpose only
// Changes if request args will change
type AuthRequestValidator interface {
	AuthorizeRequestValidate(ctx context.Context, clientID interface{}, redirectUri string, scope string, responseType string) (string, error)
	TokenArgsValidate(ctx context.Context, clientID interface{}, redirectUri string, authCode string) (err error)
}

// IPProvider saves/gets user's trusted ip via login
type IPProvider interface {
	SaveTrustedIPv4(ctx context.Context, trustedIP string) error
	GetAllUserTrustedIPv4(ctx context.Context, userID int64) ([]string, error)
	CheckUserTrustedIPv4(ctx context.Context, ipv4 string) error
}

// PKCEStorage saves/gets pkce between two endpoints: Authorize-Token
type PKCEStorage interface {
	PKCE(ctx context.Context, sessionID string) (*models.PKCE, error)
	SavePKCE(ctx context.Context, pkce *models.PKCE) error
	RemovePKCE(ctx context.Context, sessionID string) error
}

// AuthCodeStorage stores auth codes refers to user_id
type AuthCodeStorage interface {
	AuthCode(ctx context.Context, code string) (*models.AuthorizationCode, error)
	SaveAuthCode(ctx context.Context, code *models.AuthorizationCode) error
	RemoveAuthCode(ctx context.Context, userID int64) error
}
