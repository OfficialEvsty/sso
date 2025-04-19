package interfaces

import (
	"context"
	"sso/internal/domain/models"
)

// JwkProvider interface allows sign a JWT and give upon request a Public Key
type JwkProvider interface {
	SignJWT(ctx context.Context, claims map[string]interface{}, keyVersion int) (string, error)
	RotateKey(ctx context.Context) error
	LatestKeyVersion(ctx context.Context) (int, error)
	PublicKeys(ctx context.Context) ([]byte, error)
}

// VerificationStorage writes a token in storage
type VerificationStorage interface {
	SaveVerifiedUserEmail(ctx context.Context, userID int64, email string) error
}

type VerificationTokenStorage interface {
	SaveEmailToken(ctx context.Context, email string, token string) error
	DeleteEmailToken(ctx context.Context, token string) error
}

// VerificationProvider allows get a token from storage and verify user's email
type VerificationProvider interface {
	EmailToken(ctx context.Context, token string) (*models.MailAuthToken, error)
	//IsEmailVerified(ctx context.Context, userID int64) error
}
