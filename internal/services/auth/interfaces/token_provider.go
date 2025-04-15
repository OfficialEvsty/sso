package interfaces

import (
	"context"
	"sso/internal/config"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt/tokens"
)

// Token is a general interface to perform tokens
type Token interface {
	Type() config.TokenType
}

// ClaimedToken is a token with claim attributes
// Also implements Token interface
type ClaimedToken interface {
	Token
	GetClaims() map[string]interface{}
	HasClaim(claim string) bool
	ClaimValue(claim string) (interface{}, bool)
}

// TokenProvider generates JWT
type TokenProvider interface {
	MakeIDToken(user *models.User, aud string) (*tokens.IDToken, error)
	MakeAccessToken(user *models.User, aud string, scope string) (*tokens.AccessToken, error)
	MakeRefreshToken(userID int64) (*models.RefreshToken, error)
	MakeTokenSet(id *tokens.IDToken, access *tokens.AccessToken, refresh *models.RefreshToken) *tokens.TokenSet
}

// TokenStorage perform db operations
type TokenStorage interface {
	RefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	SaveRefreshToken(context.Context, *models.RefreshToken) error
	RemoveAllUserTokens(ctx context.Context, userID int64) error
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
}
