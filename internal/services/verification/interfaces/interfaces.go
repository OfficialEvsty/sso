package interfaces

import (
	"context"
	"sso/internal/domain/models"
)

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
