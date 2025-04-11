package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log/slog"
	"os"
	"slices"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/utilities"
	interfaces2 "sso/internal/services/access/interfaces"
	"sso/internal/services/auth/interfaces"
	interfaces3 "sso/internal/services/session/interfaces"
	"sso/internal/storage"
	"strconv"
	"time"
)

type Auth struct {
	log                  *slog.Logger
	usrStorage           interfaces.UserStorage
	usrProvider          interfaces.UserProvider
	appProvider          interfaces.AppProvider
	tokenCleaner         interfaces.TokenCleaner
	tokenProvider        interfaces.TokenProvider
	roleProvider         interfaces2.RoleProvider
	sessionStorage       interfaces3.SessionStorage
	tokenTTL             time.Duration
	refreshTTL           time.Duration
	sessionTTL           time.Duration
	authorizationCodeTTL time.Duration

	requestValidator interfaces.AuthRequestValidator
	ipProvider       interfaces.IPProvider
	pkceStorage      interfaces.PKCEStorage
	authCodeStorage  interfaces.AuthCodeStorage
}

// todo implement a facade pattern here
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
	sessionTTL time.Duration,
	authorizationCodeTTL time.Duration,
	requestValidator interfaces.AuthRequestValidator,
	ipProvider interfaces.IPProvider,
	pkceStorage interfaces.PKCEStorage,
	authCodeStorage interfaces.AuthCodeStorage,

) *Auth {
	return &Auth{
		usrStorage:           userStorage,
		usrProvider:          userProvider,
		appProvider:          appProvider,
		tokenCleaner:         tokenCleaner,
		tokenProvider:        tokenProvider,
		sessionStorage:       sessionStorage,
		roleProvider:         roleProvider,
		log:                  log,
		tokenTTL:             tokenTTL,
		refreshTTL:           refreshTokenTTL,
		sessionTTL:           sessionTTL,
		authorizationCodeTTL: authorizationCodeTTL,
		requestValidator:     requestValidator,
		ipProvider:           ipProvider,
		pkceStorage:          pkceStorage,
		authCodeStorage:      authCodeStorage,
	}
}

func (a *Auth) AuthorizeArgsValidate(ctx context.Context, clientID interface{}, redirectUri string, scope string, responseType string) (validScope string, err error) {
	return a.requestValidator.AuthorizeRequestValidate(ctx, clientID, redirectUri, scope, responseType)
}

// AuthorizeByCurrentSession try to get user's session from metadata and authorize user if it valid
// If current session are empty or not valid throws error
func (a *Auth) AuthorizeByCurrentSession(ctx context.Context, scope string, state string, pkce *models.PKCE) (uuid.UUID, error) {
	const op = "auth.AuthorizeByCurrentSession"
	logger := a.log.With(slog.String("op", op))
	sessionID, err := utilities.GetUserSession(ctx, logger)
	if err != nil {
		return uuid.Nil, err
	}
	logger.Info("sessionID successfully extracted from cookie")

	clientIP, err := utilities.GetClientIPFromMetadata(ctx, logger)
	if err != nil {
		return uuid.Nil, err
	}
	// checks if session valid and stores in user_sessions
	session, err := a.requestValidator.ActiveSession(ctx, sessionID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
		}
		// make a handler for this exception
		return uuid.Nil, storage.InfoUserUnauthenticated
	}
	if sessionExpires := time.Now().Unix() > session.Session.ExpiresAt.Unix(); sessionExpires {
		err = a.sessionStorage.RemoveSession(ctx, session.Session.Id.String())
		if err != nil {
			return uuid.Nil, fmt.Errorf("error while removing expired session: %w", err)
		}
		logger.Info("session expired and deleted from db")
		return uuid.Nil, storage.InfoSessionExpired
	}
	trustedIPs, err := a.ipProvider.GetAllUserTrustedIPv4(ctx, session.UserId)
	if err != nil {
		return uuid.Nil, err
	}
	// check is client's ip trusted by user
	if unknownIPv4 := !slices.Contains(trustedIPs, clientIP); unknownIPv4 {
		return uuid.Nil, storage.InfoUntrustedIPAddress
	}
	logger.Info("session approved", sessionID)
	// updates scope in existing user's session
	session.Session.Scope = scope
	sessionUID, err := a.sessionStorage.SaveOAuthSession(ctx, &session.Session)
	if err != nil {
		return uuid.Nil, err
	}
	logger.Info("session scope changed, ", slog.String("session_id", sessionUID.String()))
	// saves code challenge as pkce model bound to current session
	pkce.SessionID = sessionUID.String()
	pkce.ExpiresAt = time.Now().Add(a.authorizationCodeTTL)
	err = a.pkceStorage.SavePKCE(ctx, pkce)
	if err != nil {
		return uuid.Nil, err
	}
	// generate authorization code and saves it
	authCode := &models.AuthorizationCode{
		Code:      uuid.New(),
		UserID:    session.UserId,
		ExpiresAt: time.Now().Add(a.authorizationCodeTTL),
	}
	err = a.authCodeStorage.SaveAuthCode(ctx, authCode)
	if err != nil {
		return uuid.Nil, err
	}
	return authCode.Code, nil
}

// AuthorizeByLogin uses when user haven't active session and MUST provide his credentials to server to verify his identity
// If session successfully created server redirect user to login page
func (a *Auth) AuthorizeByLogin(ctx context.Context, clientID interface{}, redirectUri string, scope string, pkce *models.PKCE, state string) (string, string, error) {
	const op = "auth.AuthorizeByLogin"
	logger := a.log.With(slog.String("op", op))
	const loginRouteName = "oauth"
	loginRedirect := fmt.Sprintf("https://%s:%s/%s", os.Getenv("WEB_CLIENT_DOMAIN"), os.Getenv("WEB_CLIENT_PORT"), loginRouteName)
	// checks if ipv4 provided
	clientIP, err := utilities.GetClientIPFromMetadata(ctx, logger)
	if err != nil {
		return "", "", err
	}
	convClientID, err := strconv.Atoi(clientID.(string))
	if err != nil {
		return "", "", err
	}
	// create session object and saves it
	session := &models.OAuthSession{
		ClientId:  convClientID,
		Ip:        clientIP,
		Scope:     scope,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(a.sessionTTL),
	}
	sessionID, err := a.sessionStorage.SaveOAuthSession(ctx, session)
	if err != nil {
		logger.Error("error while saving session", err.Error())
		return "", "", err
	}
	// sets session metadata
	md := metadata.Pairs("new_session", sessionID.String())
	err = grpc.SendHeader(ctx, md)
	if err != nil {
		logger.Error("error while sending metadata", err.Error())
		return "", "", err
	}
	// saves additional session info: redirect, state
	sessionMetadata := &models.SessionMetadata{
		RedirectUri: redirectUri,
		State:       state,
		SessionID:   sessionID,
	}
	_, err = a.sessionStorage.SaveSessionMetadata(ctx, sessionMetadata)
	if err != nil {
		logger.Error("error while saving session metadata", err.Error())
		return "", "", err
	}
	// saves code challenge as pkce model bound to current session
	pkce.SessionID = sessionID.String()
	pkce.ExpiresAt = time.Now().Add(a.authorizationCodeTTL)
	err = a.pkceStorage.SavePKCE(ctx, pkce)
	if err != nil {
		return "", "", err
	}

	return sessionID.String(), loginRedirect, nil
}

// Token exchange models.AuthorizationCode on set of tokens: ID Token, AccessToken, RefreshToken aggregated in models.OAuthTokenSet
// OAuth2.1 specification method
// Validates authorization code, redirect uri, code verifier, after that generates three tokens, signed by client secret
func (a *Auth) Token(ctx context.Context, authCode string, grant string, redirectUri string, codeVerifier string, clientID interface{}) (string, error) {
	const op = "auth.Token"
	logger := a.log.With(slog.String("op", op))
	logger.Debug("starts exchanging authorization code on tokens set...")
	//// Getting current user's roles
	//roles, err := a.roleProvider.UserRoles(ctx, user.ID)
	//if err != nil {
	//	a.log.Error("error getting user roles, default role was returned", op, err.Error())
	//	roles = &[]string{"member"}
	//}
	//fmt.Print(roles)
	////refresh, access, err = jwt.GenerateTokenPair(user, app, *roles, a.tokenTTL)
	//
	//if err != nil {
	//	a.log.Error("failed to generate tokens", err.Error())
	//	return "", "", fmt.Errorf("%s: %w", op, err)
	//}
	//
	//err = a.tokenCleaner.RemoveAllUserTokens(ctx, user.ID)
	//if err != nil {
	//	a.log.Error("failed to remove user tokens", err.Error())
	//}
	//
	//timeToExpire := time.Now().Add(a.refreshTTL)
	//err = a.tokenProvider.CachedSaveRefreshToken(ctx, nil, user.ID, refresh, timeToExpire)
	//if err != nil {
	//	if !errors.Is(err, storage.InfoCacheDisabled) {
	//		a.log.Error("failed to save token", err.Error())
	//		return "", "", fmt.Errorf("%s: %w", op, err)
	//	}
	//}
	//
	//// not strict if error pass
	////_, err = a.sessionStorage.SaveSession(ctx, user.ID, appID, "ip", "device")
	////if err != nil {
	////	if !(errors.Is(err, storage.InfoCacheDisabled)) {
	////		a.log.Error("failed to save session", err.Error())
	////	}
	////	a.log.Warn("session was not saved, cache disabled", err.Error())
	////}
	//
	//return access, refresh, nil
	return nil, nil
}

// Login checks if user with given credentials exists in system
//
// If user exists, but password is incorrect, returns error.
// If user doesn't exist, returns error.
func (a *Auth) Login(
	ctx context.Context,
	email string,
	password string,
) (string, error) {
	const op = "auth.Login"

	logger := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	logger.Info("attempting to login user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", err.Error())

			return "", fmt.Errorf("%s: %w", op, err)
		}
		return "", fmt.Errorf("%s: %w", op, err)
	}
	logger.Info("user found")
	err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password))
	if err != nil {
		a.log.Info("invalid credentials", err.Error())
		return "", storage.ErrInvalidCredentials
	}
	logger.Info("user authorized successfully", slog.String("userID", fmt.Sprintf("%v", user.ID)))

	if !user.IsEmailVerified {
		return "", storage.ErrUserNotConfirmedEmail
	}

	logger.Info("user logged in successfully")

	const redirectRouteName = "redirect"
	redirectUri := fmt.Sprintf("https://%s:%s/%s", os.Getenv("WEB_CLIENT_DOMAIN"), os.Getenv("WEB_CLIENT_PORT"), redirectRouteName)
	// extract sessionID from cookies and validates session
	sessionID, err := utilities.GetUserSession(ctx, logger)
	if err != nil {
		return "", err
	}
	_, err = a.sessionStorage.Session(ctx, sessionID)
	if err != nil {
		if !errors.Is(err, storage.InfoSessionNotFound) {
			return "", err
		}
		// todo буквально не знаю что в этом случае делать, но нужно перессылать на главную страницу приложения, чтобы он стучался оттуда
		return redirectUri, nil
	}
	// todo сессия может быть просрочена, но так как это сессия пустышка, то не пугаемся (но не знаем что делать)
	// --extract client's IP and saves it as trusted IP address (make it step when exchange auth code on tokens)
	// gets 'state' parameter from db
	sessionMetadata, err := a.sessionStorage.SessionMetadata(ctx, sessionID)
	if err != nil {
		return "", err
	}
	stateParam := sessionMetadata.State
	// create an authorization code and saves it
	authCode := &models.AuthorizationCode{
		Code:      uuid.New(),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.authorizationCodeTTL),
	}
	err = a.authCodeStorage.SaveAuthCode(ctx, authCode)
	if err != nil {
		return "", err
	}
	// generate redirect uri with code and state as parameters
	redirectUri += fmt.Sprintf("?code=%s&state=%s", authCode.Code, stateParam)
	return redirectUri, nil
	// todo все что ниже перенести в логику Token

}

// / Register a new user and hashed password
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
	var userID int64

	// get user if exists
	user, err := a.usrProvider.User(ctx, email)
	// save user if not exists or get id of existing user
	if err != nil {
		if !errors.Is(err, storage.ErrUserNotExist) {
			log.Error("failed to get user", err.Error())
			return 0, fmt.Errorf("%s: %w", op, err)
		}

		log.Info("registering user")
		// generating password's hash
		passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Error("failed to generate password's hash", err.Error())
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		// save user
		userID, err = a.usrStorage.SaveUser(ctx, email, passHash)
		if err != nil {
			if errors.Is(err, storage.ErrUserExists) {
				log.Error(storage.ErrUserExists.Error(), err.Error())
			}
			log.Error("failed to save user", err.Error())
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		log.Info("successfully registered user")
		return userID, nil
	}

	// 3. user data exists
	if &user == nil {
		log.Error("user data is nil")
		return 0, fmt.Errorf("%s: invalid user data", op)
	}

	// checks if user verified
	if user.IsEmailVerified {
		log.Info("user already registered")
		return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
	}
	// user exists but not verified
	userID = user.ID
	return userID, nil
}

// DeleteUser deletes user and his dependencies from storage
func (a *Auth) DeleteUser(ctx context.Context, id int64) error {
	const op = "auth.DeleteUser"
	log := a.log.With(slog.String("op", op), slog.String("id", strconv.FormatInt(id, 10)))
	err := a.usrStorage.DeleteUser(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Info("user not found")
		}
		log.Error("failed to delete user", err.Error())
		return err
	}
	return nil
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

	roles, err := a.roleProvider.UserRoles(ctx, user.ID)
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
		if !errors.Is(err, storage.InfoCacheDisabled) {
			a.log.Error("failed to remove old refresh token", op, err.Error())
			return "", "", fmt.Errorf("%s: %w", op, err)
		}
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
		if !errors.Is(err, storage.InfoCacheDisabled) {
			a.log.Error("failed to save refresh token", op, err.Error())
			return "", "", fmt.Errorf("%s: %w", op, err)
		}
	}

	//_, err = a.sessionStorage.SaveSession(ctx, user.ID, appID, "ip", "device")
	//if err != nil {
	//	if !(errors.Is(err, storage.InfoCacheDisabled) || errors.Is(err, storage.InfoSessionsDisabled)) {
	//		a.log.Error("failed to save session", err.Error())
	//		return "", "", fmt.Errorf("%s: %w", op, err)
	//	}
	//}

	return access, refresh, nil
}

// CompleteLogout logout user and cleans held cache and tokens stored in database
func (a *Auth) CompleteLogout(ctx context.Context, userID int64, token string) error {
	const op = "auth.CompleteLogout"

	_, err := a.usrProvider.UserById(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Error("user not found", op, userID, err.Error())
			return storage.ErrUserNotFound
		}
		a.log.Error("failed to get user", op, userID, err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = a.tokenProvider.CachedDeleteRefreshToken(ctx, token, false)
	if err != nil {
		a.log.Error("failed to remove refresh token", op, userID, err.Error())
	}

	err = a.tokenCleaner.RemoveAllUserTokens(ctx, userID)
	if err != nil {
		a.log.Error("failed to remove user tokens", op, userID, err.Error())
	}

	a.log.Info("successfully logged out", op, userID)
	return nil
}
