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
	"net"
	"os"
	"slices"
	"sso/internal/app/interceptors"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt/tokens"
	"sso/internal/lib/utilities"
	interfaces2 "sso/internal/services/access/interfaces"
	"sso/internal/services/auth/interfaces"
	interfaces3 "sso/internal/services/session/interfaces"
	"sso/internal/storage"
	"strconv"
	"strings"
	"time"
)

type Auth struct {
	log                  *slog.Logger
	usrStorage           interfaces.UserStorage
	usrProvider          interfaces.UserProvider
	appProvider          interfaces.AppProvider
	tokenStorage         interfaces.TokenStorage
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
	tokenStorage interfaces.TokenStorage,
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
		tokenStorage:         tokenStorage,
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

// AuthorizeArgsValidate validates Authorize endpoint's request args: clientID, redirectUri, scope, responseType
func (a *Auth) AuthorizeArgsValidate(ctx context.Context, clientID interface{}, redirectUri string, scope string, responseType string) (validScope string, err error) {
	return a.requestValidator.AuthorizeRequestValidate(ctx, clientID, redirectUri, scope, responseType)
}

// AuthorizeByCurrentSession try to get user's session from metadata and authorize user if it valid
// If current session are empty or not valid throws error
func (a *Auth) AuthorizeByCurrentSession(ctx context.Context, scope string, pkce *models.PKCE) (uuid.UUID, error) {
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
	session, err := a.sessionStorage.ActiveSession(ctx, sessionID)
	if err != nil {
		if sessionRemovingErr := a.sessionStorage.RemoveSession(ctx, sessionID); sessionRemovingErr != nil {
			return uuid.Nil, fmt.Errorf("error while session must be cleaned: %w", err)
		}
		//logger.Info("invalid session cleaned", slog.String("sessionID", sessionID))
		if !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
		}
		// make a handler for this exception
		logger.Info("user's session not valid")
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
	// converting []net.IP to []string due utility Mapper
	if unknownIPv4 := !slices.Contains(utilities.Map(trustedIPs, func(ip net.IP) string {
		return ip.String()
	}), clientIP); unknownIPv4 {
		logger.Info("user trying to logged in via untrusted ip address, redirect on login form...")
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
		Scope:     scope,
	}
	err = a.authCodeStorage.RemoveAuthCode(ctx, session.UserId)
	if err != nil {
		return uuid.Nil, fmt.Errorf("error while removing auth code: %w", err)
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
	const loginRouteName = "auth"
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
		Id:        uuid.New(),
		ClientId:  convClientID,
		Ip:        net.ParseIP(clientIP),
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

// TokenArgsValidate validates Token endpoint's args: clientID, redirectUri, state
func (a *Auth) TokenArgsValidate(
	ctx context.Context,
	clientID interface{},
	redirectUri string,
	codeVerifier string,
	sessionID string,
) (err error) {
	return a.requestValidator.TokenArgsValidate(ctx, clientID, redirectUri, codeVerifier, sessionID)
}

func (a *Auth) RefreshTokenArgsValidate(
	ctx context.Context,
	clientID interface{},
	clientSecret string,
) (err error) {
	const op = "auth.RefreshTokenArgsValidate"
	logger := a.log.With(slog.String("op", op))
	logger.Debug("starts validating refresh token args...")
	err = a.requestValidator.RefreshTokenArgsValidate(ctx, clientID, clientSecret)
	logger.Info("successfully validated refresh token args")
	return err
}

// Token exchange models.AuthorizationCode on set of tokens: ID Token, AccessToken, RefreshToken aggregated in models.OAuthTokenSet
// OAuth2.1 specification method
// Validates authorization code, redirect uri, code verifier, after that generates three tokens, signed by client secret
func (a *Auth) Token(ctx context.Context, authCode string, redirectUri string, codeVerifier string, clientID string) (set *tokens.TokenSet, err error) {
	const op = "auth.Token"
	aud := "currently unimplemented"
	logger := a.log.With(slog.String("op", op))
	logger.Debug("starts exchanging authorization code on tokens set...")
	logger.Debug("validates args...")
	sessionID, err := utilities.GetUserSession(ctx, logger)
	if err != nil {
		return nil, err
	}
	// validates args: hash codeVerifier, checks redirect uri, authCode and clientID
	err = a.TokenArgsValidate(ctx, clientID, redirectUri, codeVerifier, sessionID)
	if err != nil {
		return set, err
	}
	logger.Debug("provided args valid")
	// gets auth code, extract user id
	code, err := a.authCodeStorage.AuthCode(ctx, authCode)
	if err != nil {
		return set, fmt.Errorf("error while receiving auth code: %w", err)
	}
	logger.Debug("received auth code")
	// gets user by user id
	user, err := a.usrProvider.UserById(ctx, code.UserID)
	if err != nil {
		if !errors.Is(err, storage.ErrUserNotFound) {
			return set, fmt.Errorf("error while receiving user: %w", err)
		}
		return set, storage.ErrUserNotFound
	}
	// checks allowed user's scope
	convClientID, err := strconv.Atoi(clientID)
	if err != nil {
		return nil, err
	}

	allowedScope, err := a.roleProvider.AllowedUserScope(ctx, code.UserID, convClientID)
	if err != nil {
		return set, fmt.Errorf("error while receiving user roles: %w", err)
	}
	logger.Debug("user's allowed scope: %w", strings.Join(allowedScope, " "))
	requestedScope := strings.Split(code.Scope, " ")
	var resultScopeSlice []string
	for _, claim := range requestedScope {
		if slices.Contains(allowedScope, claim) {
			resultScopeSlice = append(resultScopeSlice, claim)
		}
	}
	resultScope := strings.Join(resultScopeSlice, " ")
	// generate tokens set (id, access, refresh)
	idToken, err := a.tokenProvider.MakeIDToken(ctx, &user, aud)
	if err != nil {
		return nil, fmt.Errorf("error generating id token: %w", err)
	}
	logger.Debug("idToken generated")
	acsToken, err := a.tokenProvider.MakeAccessToken(ctx, &user, aud, resultScope)
	if err != nil {
		return nil, fmt.Errorf("error generating access token: %w", err)
	}
	logger.Debug("access token generated")
	refresh, err := a.tokenProvider.MakeRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("error generating refresh token: %w", err)
	}
	tokenSet := a.tokenProvider.MakeTokenSet(idToken, acsToken, refresh)
	// saves refresh token
	err = a.tokenStorage.RemoveAllUserTokens(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("error removing user's refresh tokens: %w", err)
	}

	err = a.tokenStorage.SaveRefreshToken(ctx, refresh)
	if err != nil {
		return nil, fmt.Errorf("error saving refresh token: %w", err)
	}

	// cleaning all unnecessary data
	err = a.authCodeStorage.RemoveAuthCode(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("error removing auth code: %w", err)
	}
	err = a.sessionStorage.RemoveSessionMetadata(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("error removing session's metadata: %w", err)
	}
	err = a.pkceStorage.RemovePKCE(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("error removing pkce: %w", err)
	}
	return tokenSet, nil
}

// RefreshToken refreshes AccessToken by RefreshToken and rotates it
// OAuth2.1 specification method
// Validates refresh token, client id and client secret
func (a *Auth) RefreshToken(ctx context.Context, token string, clientID interface{}, clientSecret string) (set *tokens.TokenSet, err error) {
	const op = "auth.RefreshToken"
	logger := a.log.With(slog.String("op", op))
	logger.Debug("starts refreshing tokens set...")
	// validation
	err = a.RefreshTokenArgsValidate(ctx, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("error while validating grant_type: refresh_token, token endpoint: %w", err)
	}
	// checks whether exist user's authorized session (active/alive)
	sessionID, err := utilities.GetUserSession(ctx, logger)
	if err != nil {
		return nil, storage.InfoSessionNotFound
	}

	refreshToken, err := a.tokenStorage.RefreshToken(ctx, token)
	if err != nil {
		logger.Error("error while getting refresh token: %w", err)
		return nil, fmt.Errorf("error while refreshing token: %w", err)
	}
	session, err := a.sessionStorage.ActiveSession(ctx, sessionID)
	if err != nil {
		logger.Error("error while getting active session: %w", err)
		return nil, fmt.Errorf("error while getting active session: %w", err)
	}
	if session.UserId != refreshToken.UserID {
		logger.Warn("user's session not related to refresh token's user. (IMPORTANT)")
		return nil, fmt.Errorf("user's session not related to refresh token's user. (IMPORTANT)")
	}
	// checks if session expired
	if session.Session.ExpiresAt.Unix() < time.Now().Unix() {
		err = a.sessionStorage.RemoveSession(ctx, sessionID)
		if err != nil {
			logger.With("session_id", sessionID).Error("error while removing expired session: %w", err)
			return nil, fmt.Errorf("error while removing expired session: %w", err)
		}
		return nil, storage.InfoSessionExpired
	}
	// checks if token not expired
	if refreshToken.ExpiresAt.Unix() < time.Now().Unix() {
		logger.Error("refresh token expired")
		return nil, storage.ErrTokenExpired
	}
	// checks if user exist
	user, err := a.usrProvider.UserById(ctx, refreshToken.UserID)
	if err != nil {
		logger.Error("error while validating user: %w", err)
		return nil, storage.ErrUserNotFound
	}

	// generating access token
	acsToken, err := a.tokenProvider.MakeAccessToken(ctx, &user, "currently not implemented", session.Session.Scope)
	if err != nil {
		logger.Error("error generating access token: %w", err)
		return nil, fmt.Errorf("error generating access token: %w", err)
	}
	// generating new refresh token
	newRefreshToken, err := a.tokenProvider.MakeRefreshToken(user.ID)
	if err != nil {
		logger.Error("error generating refresh token: %w", err)
		return nil, fmt.Errorf("error generating refresh token: %w", err)
	}
	// rotating refresh token
	err = a.tokenStorage.UpdateRefreshToken(ctx, newRefreshToken)
	if err != nil {
		logger.Error("error updating refresh token: %w", err)
		return nil, fmt.Errorf("error updating refresh token: %w", err)
	}
	set = a.tokenProvider.MakeTokenSet(nil, acsToken, newRefreshToken)
	return set, nil
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
	env := utilities.EnvFromContext(ctx)
	logger := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
		slog.String("env", env),
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

	if env == interceptors.EnvProd {
		if !user.IsEmailVerified {
			return "", storage.ErrUserNotConfirmedEmail
		}
	}

	logger.Info("user logged in successfully")
	// extract sessionID from cookies and validates session
	sessionID, err := utilities.GetUserSession(ctx, logger)
	if err != nil {
		return "", fmt.Errorf("error while getting user's session from request metadata: %w", err)
	}
	session, err := a.sessionStorage.Session(ctx, sessionID)
	if err != nil {
		if !errors.Is(err, storage.InfoSessionNotFound) {
			return "", err
		}
		// todo буквально не знаю что в этом случае делать, но нужно перессылать на главную страницу приложения, чтобы он стучался оттуда
		return "", fmt.Errorf("error while getting session from db: %w", err)
	}

	// todo сессия может быть просрочена, но так как это сессия пустышка, то не пугаемся (но не знаем что делать)
	// --extract client's IP and saves it as trusted IP address (make it step when exchange auth code on tokens)
	clientIP, err := utilities.GetClientIPFromMetadata(ctx, logger)
	if err != nil {
		return "", err
	}
	// gets 'state' parameter from db
	sessionMetadata, err := a.sessionStorage.SessionMetadata(ctx, sessionID)
	if err != nil {
		return "", err
	}
	logger.Debug("session's metadata successfully received", slog.String("sessionID", sessionID))
	redirectUri := fmt.Sprintf("%s/%s", sessionMetadata.RedirectUri)
	stateParam := sessionMetadata.State
	// create an authorization code and saves it
	authCode := &models.AuthorizationCode{
		Code:      uuid.New(),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(a.authorizationCodeTTL),
		Scope:     session.Scope,
	}
	err = a.authCodeStorage.RemoveAuthCode(ctx, user.ID)
	if err != nil {
		return "", fmt.Errorf("error while removing auth code: %w", err)
	}
	err = a.authCodeStorage.SaveAuthCode(ctx, authCode)
	logger.Info("auth code saved successfully", slog.String("scope", session.Scope))
	if err != nil {
		return "", err
	}
	// add current client ip to list of trusted user's ips
	err = a.ipProvider.CheckUserTrustedIPv4(ctx, clientIP)
	if err != nil {
		if !errors.Is(err, storage.InfoTrustedIPNotFound) {
			return "", fmt.Errorf("error while checking trusted IP: %w", err)
		}
		err = a.ipProvider.SaveTrustedIPv4(ctx, clientIP, user.ID)
		if err != nil {
			return "", err
		}
		logger.Info("user added new trusted ip")
	}
	// deletes previous authenticated sessions
	err = a.sessionStorage.RemoveAllUserSessionsExceptCurrent(ctx, user.ID, sessionID)
	if err != nil {
		return "", err
	}
	// authenticated current user's session
	err = a.sessionStorage.AuthenticateUserSession(ctx, sessionID, user.ID)
	if err != nil {
		return "", fmt.Errorf("error while autenticated user's session: %w", err)
	}
	logger.Info("user authenticated successfully", slog.String("sessionID", fmt.Sprintf("%v", sessionID)))
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
//func (a *Auth) ValidateRefreshToken(ctx context.Context, oldRefreshToken string) (int64, error) {
//	const op = "auth.ValidateRefreshToken"
//
//	// get stored refresh token to validate received user's token
//	storedOldRefreshToken, err := a.tokenProvider.CachedRefreshToken(
//		ctx,
//		oldRefreshToken,
//	)
//	if err != nil {
//		a.log.Error("failed to get refresh token ", err.Error(), op, oldRefreshToken)
//		return 0, storage.ErrTokenInvalid
//	}
//
//	// if refresh token expired
//	if storedOldRefreshToken.ExpiresAt.Unix() < time.Now().Unix() {
//		a.log.Info("refresh token expired", op, oldRefreshToken)
//		_, err := a.tokenProvider.CachedDeleteRefreshToken(ctx, oldRefreshToken, false)
//		if err != nil {
//			return 0, fmt.Errorf("%s: %w", op, err)
//		}
//		return 0, storage.ErrTokenExpired
//	}
//	return storedOldRefreshToken.UserID, nil
//}

// UpdateTokens updates expired access token and refresh token (if it not yet expired)
// Deletes old entity of refresh token in database and writes new one
// Returns both tokens access and refresh to user
//func (a *Auth) UpdateTokens(ctx context.Context,
//	oldRefreshToken string,
//	userID int64,
//	appID int32,
//) (access string, refresh string, err error) {
//	const op = "auth.UpdateTokens"
//
//	// Gets user from storage
//
//	user, err := a.usrProvider.UserById(ctx, userID)
//	if err != nil {
//		if errors.Is(err, storage.ErrUserNotFound) {
//			a.log.Warn("user not found", err.Error())
//		}
//		return "", "", fmt.Errorf("%s: %w", op, err)
//	}
//
//	app, err := a.appProvider.App(ctx, appID)
//	if err != nil {
//		if errors.Is(err, storage.ErrAppNotFound) {
//			a.log.Warn("app not found", err.Error())
//		}
//		return "", "", fmt.Errorf("%s: %w", op, err)
//	}
//
//	roles, err := a.roleProvider.AllowedUserScope(ctx, user.ID, appID)
//	if err != nil {
//		a.log.Error("error getting user roles", op, err.Error())
//		return "", "", fmt.Errorf("%s: %w", op, err)
//	}
//
//	refresh, access, err = jwt.GenerateTokenPair(user, app, roles, a.tokenTTL)
//	if err != nil {
//		a.log.Error("failed to generate tokens", op, err.Error())
//		return "", "", fmt.Errorf("%s: %w", op, err)
//	}
//	tx, err := a.tokenProvider.CachedDeleteRefreshToken(ctx, oldRefreshToken, true)
//
//	if err != nil {
//		if !errors.Is(err, storage.InfoCacheDisabled) {
//			a.log.Error("failed to remove old refresh token", op, err.Error())
//			return "", "", fmt.Errorf("%s: %w", op, err)
//		}
//	}
//
//	timeToExpire := time.Now().Add(a.refreshTTL)
//	var txSafe pgx.Tx
//	if tx == nil {
//		txSafe = nil
//	} else {
//		txSafe = *tx
//	}
//	err = a.tokenProvider.CachedSaveRefreshToken(ctx, txSafe, user.ID, refresh, timeToExpire)
//	if err != nil {
//		if !errors.Is(err, storage.InfoCacheDisabled) {
//			a.log.Error("failed to save refresh token", op, err.Error())
//			return "", "", fmt.Errorf("%s: %w", op, err)
//		}
//	}
//
//	//_, err = a.sessionStorage.SaveSession(ctx, user.ID, appID, "ip", "device")
//	//if err != nil {
//	//	if !(errors.Is(err, storage.InfoCacheDisabled) || errors.Is(err, storage.InfoSessionsDisabled)) {
//	//		a.log.Error("failed to save session", err.Error())
//	//		return "", "", fmt.Errorf("%s: %w", op, err)
//	//	}
//	//}
//
//	return access, refresh, nil
//}

//// CompleteLogout logout user and cleans held cache and tokens stored in database
//func (a *Auth) CompleteLogout(ctx context.Context, userID int64, token string) error {
//	const op = "auth.CompleteLogout"
//
//	_, err := a.usrProvider.UserById(ctx, userID)
//	if err != nil {
//		if errors.Is(err, storage.ErrUserNotFound) {
//			a.log.Error("user not found", op, userID, err.Error())
//			return storage.ErrUserNotFound
//		}
//		a.log.Error("failed to get user", op, userID, err.Error())
//		return fmt.Errorf("%s: %w", op, err)
//	}
//
//	_, err = a.tokenProvider.CachedDeleteRefreshToken(ctx, token, false)
//	if err != nil {
//		a.log.Error("failed to remove refresh token", op, userID, err.Error())
//	}
//
//	err = a.tokenCleaner.RemoveAllUserTokens(ctx, userID)
//	if err != nil {
//		a.log.Error("failed to remove user tokens", op, userID, err.Error())
//	}
//
//	a.log.Info("successfully logged out", op, userID)
//	return nil
//}
