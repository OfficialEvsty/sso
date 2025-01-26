package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log           *slog.Logger
	usrStorage    UserStorage
	usrProvider   UserProvider
	appProvider   AppProvider
	tokenProvider TokenProvider
	tokenTTL      time.Duration
}

type UserStorage interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, uid int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appId int32) (app models.App, err error)
}

type TokenProvider interface {
	RefreshToken(ctx context.Context, token string) (refreshToken models.RefreshToken, err error)
	RemoveRefreshToken(ctx context.Context, token string) (bool, error)
	SaveRefreshToken(ctx context.Context, userID int64, token string, expiresAt int64) (int64, error)
}

var (
	ErrInvalidCredentials = "invalid credentials"
)

// New returns a new instance of the Auth service
func New(
	log *slog.Logger,
	userStorage UserStorage,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrStorage:  userStorage,
		usrProvider: userProvider,
		appProvider: appProvider,
		log:         log,
		tokenTTL:    tokenTTL,
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

	access, refresh, err = jwt.GenerateTokenPair(user, app, a.tokenTTL)

	if err != nil {
		a.log.Error("failed to generate tokens", err.Error())
		return "", "", fmt.Errorf("%s: %w", op, err)
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

// RefreshTokensPair refreshes both tokens access and refresh
func (a *Auth) RefreshTokensPair(ctx context.Context, oldRefreshToken string) (refresh string, access string, err error) {
	const op = "auth.RefreshTokensPair"
	storedOldRefreshToken, err := a.tokenProvider.RefreshToken(
		ctx,
		oldRefreshToken,
	)
	if err != nil {
		a.log.Error("failed to refresh token pair", err.Error(), op, oldRefreshToken)
		return "", "", errors.New("failed to refresh token:" + err.Error())
	}

	return refresh, access, nil
}
