package verification

import (
	"context"
	"log/slog"
	interfaces2 "sso/internal/services/auth/interfaces"
	"sso/internal/services/verification/interfaces"
	"strings"
)

type Verification struct {
	log          *slog.Logger
	storage      interfaces.VerificationStorage
	tokenStorage interfaces.VerificationTokenStorage
	provider     interfaces.VerificationProvider
	userProvider interfaces2.UserProvider
}

// New creates an instance of Verification service
func New(
	logger *slog.Logger,
	storage interfaces.VerificationStorage,
	tokenStorage interfaces.VerificationTokenStorage,
	provider interfaces.VerificationProvider,
	userProvider interfaces2.UserProvider,
) *Verification {
	return &Verification{
		log:          logger,
		storage:      storage,
		tokenStorage: tokenStorage,
		provider:     provider,
		userProvider: userProvider,
	}
}

// SaveEmailToken writes token data in storage
func (v *Verification) SaveEmailToken(ctx context.Context, email string, token string) error {
	op := "verification.SaveEmailToken"
	mailSliced := strings.Split(email, "@")
	mailProvider := "not stated"
	if len(mailSliced) > 1 {
		mailProvider = mailSliced[1]
	}
	logger := v.log.With(slog.String("op", op), slog.String("email-provider", mailProvider))
	logger.Info("token successfully saved")
	err := v.tokenStorage.SaveEmailToken(ctx, email, token)
	if err != nil {
		logger.Error("error saving email token", err)
		return err
	}
	return nil
}

// VerifyEmail deletes email token and confirms user's email
func (v *Verification) VerifyEmail(ctx context.Context, token string) error {
	op := "verification.VerifyEmail"
	logger := v.log.With(slog.String("op", op))
	eToken, err := v.provider.EmailToken(ctx, token)
	if err != nil {
		logger.Error("error verifying email token", err)
		return err
	}
	email := eToken.Email
	mailSliced := strings.Split(email, "@")
	mailProvider := "not stated"
	if len(mailSliced) > 1 {
		mailProvider = mailSliced[1]
	}
	logger.Info("email-provider verified as", slog.String("email", mailProvider))
	user, err := v.userProvider.User(ctx, email)
	if err != nil {
		logger.Error("error getting user", err)
		return err
	}
	err = v.storage.SaveVerifiedUserEmail(ctx, user.ID, user.Email)
	if err != nil {
		logger.Error("error saving verified user email", err)
		return err
	}
	// clear stored token in cache
	err = v.tokenStorage.DeleteEmailToken(ctx, token)
	if err != nil {
		logger.Error("error deleting email token", err)
	}
	return nil
}
