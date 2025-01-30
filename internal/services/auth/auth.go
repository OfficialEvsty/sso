package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/lib/jwt"
	interfaces2 "sso/internal/services/access/interfaces"
	"sso/internal/services/auth/interfaces"
	interfaces3 "sso/internal/services/session/interfaces"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log            *slog.Logger
	usrStorage     interfaces.UserStorage
	usrProvider    interfaces.UserProvider
	appProvider    interfaces.AppProvider
	tokenCleaner   interfaces.TokenCleaner
	tokenProvider  interfaces.TokenProvider
	roleProvider   interfaces2.RoleProvider
	sessionStorage interfaces3.SessionStorage
	tokenTTL       time.Duration
	refreshTTL     time.Duration
}

var (
	ErrInvalidCredentials = "invalid credentials"
)

// New returns a new instance of the Auth service
func New(
	log *slog.Logger,
	userStorage interfaces.UserStorage,
	userProvider interfaces.UserProvider,
	appProvider interfaces.AppProvider,
	tokenCleaner interfaces.TokenCleaner,
	tokenProvider interfaces.TokenProvider,
	sessionStorage interfaces3.SessionStorage,
	roleProvider interfaces2.RoleProvider,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrStorage:     userStorage,
		usrProvider:    userProvider,
		appProvider:    appProvider,
		tokenCleaner:   tokenCleaner,
		tokenProvider:  tokenProvider,
		sessionStorage: sessionStorage,
		roleProvider:   roleProvider,
		log:            log,
		tokenTTL:       tokenTTL,
		refreshTTL:     refreshTokenTTL,
	}
}

// Login checks if user with given credentials exists in system
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
	appID int32,
) (access string, refresh string, err error) {
	const op = "auth.Login"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err.Error())

			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.With(op).Info("user found")

	err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password))
	if err != nil {
		a.log.Info("invalid credentials", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	log.Info("token generated successfully")
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Error(storage.ErrAppNotFound.Error(), err.Error())
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	// Getting current user's roles
	roles, err := a.roleProvider.UserRoles(ctx, user.ID, appID)
	if err != nil {
		a.log.Error("error getting user roles, default role was returned", op, err.Error())
		roles = &[]string{"member"}
	}
	refresh, access, err = jwt.GenerateTokenPair(user, app, *roles, a.tokenTTL)

	if err != nil {
		a.log.Error("failed to generate tokens", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.tokenCleaner.RemoveAllUserTokens(ctx, user.ID)
	if err != nil {
		a.log.Error("failed to remove user tokens", err.Error())
	}

	timeToExpire := time.Now().Add(a.refreshTTL)
	err = a.tokenProvider.CachedSaveRefreshToken(ctx, nil, user.ID, refresh, timeToExpire)
	if err != nil {
		a.log.Error("failed to save token", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	// not strict if error pass
	_, err = a.sessionStorage.SaveSession(ctx, user.ID, appID, "ip", "device")
	if err != nil {
		if !(errors.Is(err, storage.InfoCacheDisabled)) {
			a.log.Error("failed to save session", err.Error())
		}
		a.log.Warn("session was not saved, cache disabled", err.Error())
	}

	return access, refresh, nil
}

// / Register a new user and hashed password
// /
// / Returns user's id
// / Save user in a local storage (database)
func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password's hash", err.Error())

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrStorage.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Error(storage.ErrUserExists.Error(), err.Error())
		}
		log.Error("failed to save user", err.Error())
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("successfully registered user")
	return id, nil
}

// IsAdmin checks whether this user an admin
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "auth.IsAdmin"
	log := a.log.With(slog.String("op", op),
		slog.Int64("user_id", userID))
	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checking if user is admin", slog.Bool("isAdmin", isAdmin))

	return isAdmin, nil
}

// ValidateRefreshToken validate refresh token
//
// Returns user's ID if token valid, else 0
func (a *Auth) ValidateRefreshToken(ctx context.Context, oldRefreshToken string) (int64, error) {
	const op = "auth.ValidateRefreshToken"

	// get stored refresh token to validate received user's token
	storedOldRefreshToken, err := a.tokenProvider.CachedRefreshToken(
		ctx,
		oldRefreshToken,
	)
	if err != nil {
		a.log.Error("failed to get refresh token ", err.Error(), op, oldRefreshToken)
		return 0, storage.ErrTokenInvalid
	}

	// if refresh token expired
	if storedOldRefreshToken.ExpiresAt.Unix() < time.Now().Unix() {
		a.log.Info("refresh token expired", op, oldRefreshToken)
		_, err := a.tokenProvider.CachedDeleteRefreshToken(ctx, oldRefreshToken, false)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		return 0, storage.ErrTokenExpired
	}
	return storedOldRefreshToken.UserID, nil
}

// UpdateTokens updates expired access token and refresh token (if it not yet expired)
// Deletes old entity of refresh token in database and writes new one
// Returns both tokens access and refresh to user
func (a *Auth) UpdateTokens(ctx context.Context,
	oldRefreshToken string,
	userID int64,
	appID int32,
) (access string, refresh string, err error) {
	const op = "auth.UpdateTokens"

	// Gets user from storage

	user, err := a.usrProvider.UserById(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err.Error())
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", err.Error())
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	roles, err := a.roleProvider.UserRoles(ctx, user.ID, appID)
	if err != nil {
		a.log.Error("error getting user roles", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	refresh, access, err = jwt.GenerateTokenPair(user, app, *roles, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate tokens", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	tx, err := a.tokenProvider.CachedDeleteRefreshToken(ctx, oldRefreshToken, true)

	if err != nil {
		a.log.Error("failed to remove old refresh token", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	timeToExpire := time.Now().Add(a.refreshTTL)
	var txSafe pgx.Tx
	if tx == nil {
		txSafe = nil
	} else {
		txSafe = *tx
	}
	err = a.tokenProvider.CachedSaveRefreshToken(ctx, txSafe, user.ID, refresh, timeToExpire)
	if err != nil {
		a.log.Error("failed to save refresh token", op, err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	_, err = a.sessionStorage.SaveSession(ctx, user.ID, appID, "ip", "device")
	if err != nil {
		a.log.Error("failed to save session", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return access, refresh, nil
}
