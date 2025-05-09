package auth

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log"
	"sso/internal/api/mail"
	"sso/internal/app/interceptors"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/utilities"
	"sso/internal/services/auth"
	"sso/internal/services/session"
	"sso/internal/services/verification"
	"sso/internal/storage"
)

/*type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
	UpdateTokens(
		ctx context.Context,
		userToken string,
		userID int64,
		appID int,
	) (access string, refresh string, err error)
	ValidateRefreshToken(
		ctx context.Context,
		oldRefreshToken string,
	) (int64, error)
}*/

const (
	emptyValue = 0
)

type serverAPI struct {
	ssov1.UnimplementedAuthServiceServer
	auth         auth.Auth
	verification verification.Verification
	mailer       mail.MailClient
	s            session.Session
}

func Register(gRPC *grpc.Server, auth *auth.Auth, verification *verification.Verification, mailer *mail.MailClient) {
	ssov1.RegisterAuthServiceServer(gRPC, &serverAPI{auth: *auth, verification: *verification, mailer: *mailer})
}

// Token OAuth2.1 specification exchanges Authorization Code on Tokens handler
// Receive ID, Access and Refresh tokens signed by private key of RS256 method
func (s *serverAPI) Token(ctx context.Context, req *ssov1.TokenRequest) (*ssov1.TokenResponse, error) {
	// check preconditions (fields MUST NOT be empty)
	switch req.GrantType.(type) {
	case *ssov1.TokenRequest_AuthorizationCode:
		authCodeReq := req.GetAuthorizationCode()
		err := validateAuthorizationCodeOnEmptyFields(authCodeReq)
		if err != nil {
			return nil, err
		}
		set, err := s.auth.Token(
			ctx,
			authCodeReq.GetAuthCode(),
			authCodeReq.GetRedirectUri(),
			authCodeReq.GetCodeVerifier(),
			authCodeReq.GetClientId(),
		)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}

		return &ssov1.TokenResponse{
			IdToken:      set.ID.Token,
			AccessToken:  set.Access.Token,
			RefreshToken: set.Refresh.Token,
			ExpiresIn:    uint32(set.Access.ExpiresAt.Unix()),
			TokenType:    "Bearer",
		}, nil
	case *ssov1.TokenRequest_RefreshToken:
		refreshReq := req.GetRefreshToken()
		// validate on empty
		err := validateRefreshTokenOnEmptyFields(refreshReq)
		if err != nil {
			return nil, err
		}
		set, err := s.auth.RefreshToken(ctx, refreshReq.GetRefreshToken(), refreshReq.GetClientId(), refreshReq.GetClientSecret())
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return &ssov1.TokenResponse{
			AccessToken:  set.Access.Token,
			RefreshToken: set.Refresh.Token,
			ExpiresIn:    uint32(set.Access.ExpiresAt.Unix()),
			TokenType:    "Bearer",
		}, nil
	default:
		return nil, status.Error(codes.NotFound, "unsupported")
	}
}

// validateTokenRequestOnEmptyFields validates token request on empty fields
func validateAuthorizationCodeOnEmptyFields(req *ssov1.AuthorizationCodeGrant) error {
	if req.GetClientId() == "" {
		return status.Error(codes.InvalidArgument, "client id is empty")
	}
	if req.GetRedirectUri() == "" {
		return status.Error(codes.InvalidArgument, "redirect uri is empty")
	}
	if req.GetAuthCode() == "" {
		return status.Error(codes.InvalidArgument, "auth code is empty")
	}
	if req.GetCodeVerifier() == "" {
		return status.Error(codes.InvalidArgument, "code verifier is empty")
	}
	return nil
}

// validateTokenRequestOnEmptyFields validates token request on empty fields
func validateRefreshTokenOnEmptyFields(req *ssov1.RefreshTokenGrant) error {
	if req.GetClientId() == "" {
		return status.Error(codes.InvalidArgument, "client id is empty")
	}
	if req.GetRefreshToken() == "" {
		return status.Error(codes.InvalidArgument, "token is empty")
	}
	if req.GetClientSecret() == "" {
		return status.Error(codes.InvalidArgument, "client secret is empty")
	}
	return nil
}

// Authorize OAuth2.1 specification authorization method
// If user has the active session simplify redirects with authorization code
// Else creates initial session and redirects user on login page
// Throw error if faces unpredictably behaviour
func (s *serverAPI) Authorize(ctx context.Context, req *ssov1.AuthorizeRequest) (*ssov1.AuthorizeResponse, error) {
	// check preconditions (fields MUST NOT be empty)
	err := validateAuthorizeRequestOnEmptyFields(req)
	if err != nil {
		return nil, err
	}
	// check fields and returns valid scope
	validScope, err := s.auth.AuthorizeArgsValidate(ctx, req.GetClientId(), req.GetRedirectUri(), req.GetScope(), req.GetResponseType())
	if err != nil {
		return nil, err
	}
	pkce, err := parsePKCE(req.GetCodeChallenge(), req.GetCodeChallengeMethod())
	if err != nil {
		return nil, err
	}
	code, err := s.auth.AuthorizeByCurrentSession(ctx, validScope, pkce)
	if err != nil {
		//noInterruptingErrors := []error {storage.InfoUserUnauthenticated, pgx.ErrNoRows} хорошая была задумка, но можно проще
		if errors.Is(err, storage.ErrNoMetadataContext) {
			return nil, status.Error(codes.InvalidArgument, "no metadata context by specified key")
		}
		if !(errors.Is(err, storage.InfoUserUnauthenticated) || errors.Is(err, storage.InfoSessionNotFound)) {
			return nil, status.Error(codes.Internal, err.Error())
		}

		// todo delete all user's sessions when redirect on login form
		sessionID, loginUri, err := s.auth.AuthorizeByLogin(ctx, req.GetClientId(), req.GetRedirectUri(), validScope, pkce, req.GetState())
		return &ssov1.AuthorizeResponse{
			Response: &ssov1.AuthorizeResponse_AuthRequired{
				AuthRequired: &ssov1.AuthenticationRequired{
					LoginUrl:  loginUri,
					SessionId: sessionID,
				},
			},
		}, err
	}
	return &ssov1.AuthorizeResponse{
		Response: &ssov1.AuthorizeResponse_Success{
			Success: &ssov1.SuccessResponse{
				RedirectUri: req.RedirectUri + "?code=" + code.String() + "&state=" + req.GetState(),
				Code:        code.String(),
				State:       req.GetState(),
			},
		},
	}, nil
}

// validateAuthorizeRequest provide request args validation
func validateAuthorizeRequestOnEmptyFields(req *ssov1.AuthorizeRequest) error {
	if req.GetClientId() == "" {
		return status.Error(codes.InvalidArgument, "missing client id")
	}
	if req.GetRedirectUri() == "" {
		return status.Error(codes.InvalidArgument, "missing redirect uri")
	}
	if req.GetResponseType() == "" {
		return status.Error(codes.InvalidArgument, "missing response type")
	}
	if req.GetState() == "" {
		return status.Error(codes.InvalidArgument, "missing state")
	}
	if req.GetCodeChallengeMethod() == "" {
		return status.Error(codes.InvalidArgument, "missing code challenge_method")
	}
	if req.GetScope() == "" {
		return status.Error(codes.InvalidArgument, "missing scope")
	}
	if req.GetCodeChallenge() == "" {
		return status.Error(codes.InvalidArgument, "missing code challenge")
	}
	return nil
}

func parsePKCE(code string, method string) (*models.PKCE, error) {
	pkce := &models.PKCE{
		CodeChallenge: code,
		Method:        method,
	}
	return pkce, nil
}

// Login's handler
func (s *serverAPI) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing email")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing password")
	}
	redirectUriWithCode, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotConfirmedEmail) {
			return nil, status.Error(codes.PermissionDenied, "user not confirmed email")
		}
		if errors.Is(err, storage.ErrUserNotExist) {
			return nil, status.Error(codes.NotFound, "user does not exist")
		}
		if errors.Is(err, storage.ErrInvalidCredentials) {
			return nil, status.Error(codes.PermissionDenied, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, fmt.Sprint("permission denied, error: ", err.Error()))
	}

	// sending metadata pairs as headers
	//md := metadata.Pairs("refresh-token", refresh)
	//err = grpc.SendHeader(ctx, md)
	//if err != nil {
	//	return nil, status.Error(codes.Internal, "failed to send header metadata")
	//}

	//todo переделать
	return &ssov1.LoginResponse{
		RedirectUri: redirectUriWithCode,
	}, nil
}

// Register's handler
func (s *serverAPI) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing email")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing password")
	}
	if req.GetCallbackUrl() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing callback url")
	}
	env := utilities.EnvFromContext(ctx)
	// registering a user
	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			fmt.Print(err.Error())
			return nil, status.Error(codes.AlreadyExists, "user exists")
		}
		fmt.Print(err.Error())
		return nil, status.Error(codes.Internal, "permission denied")
	}

	var operationsSuccessful bool
	defer func() {
		if !operationsSuccessful {
			// Если что-то пошло не так — удаляем пользователя
			if err := s.auth.DeleteUser(ctx, userID); err != nil {
				log.Printf("Failed to rollback user registration: %v", err)
			}
			log.Println("rollback user registration success")
		}
	}()

	if env != interceptors.EnvProd {
		operationsSuccessful = true
		return &ssov1.RegisterResponse{UserId: userID}, nil
	}
	// generating token
	token, err := jwt.NewVerifyingToken()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to verify token")
	}

	// saving token
	err = s.verification.SaveEmailToken(ctx, req.GetEmail(), token)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to save email token")
	}

	// send mail
	callbackUrlWithToken := req.GetCallbackUrl() + token
	err = s.mailer.SendVerificationMail(ctx, req.GetEmail(), callbackUrlWithToken)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send verification mail")
	}
	operationsSuccessful = true
	return &ssov1.RegisterResponse{UserId: userID}, nil
}

// Is Admin handler
func (s *serverAPI) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if req.GetUserId() <= emptyValue {
		return nil, status.Error(codes.InvalidArgument, "wrong or negative user id")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

// todo переделать
// RefreshToken handler updates user's tokens by receiving refresh token from user
func (s *serverAPI) RefreshToken(
	ctx context.Context,
	req *ssov1.RefreshTokenRequest,
) (*ssov1.RefreshTokenResponse, error) {
	userToken := req.GetRefreshToken()
	//appID := req.GetAppId()
	if userToken == "" {
		return nil, status.Error(codes.InvalidArgument, "missing refresh token")
	}
	//userID, err := s.auth.ValidateRefreshToken(ctx, userToken)
	//
	//if err != nil {
	//	if errors.Is(err, storage.ErrTokenExpired) {
	//		return nil, status.Error(codes.FailedPrecondition, "refresh token expired")
	//	}
	//	if errors.Is(err, storage.ErrTokenInvalid) {
	//		return nil, status.Error(codes.FailedPrecondition, "invalid refresh token")
	//	}
	//	if errors.Is(err, storage.ErrUserNotFound) {
	//		return nil, status.Error(codes.NotFound, "user not found")
	//	}
	//	return nil, status.Error(codes.Internal, "internal server error")
	//}

	//access, refresh, err := s.auth.UpdateTokens(ctx, userToken, userID, appID)
	//if err != nil {
	//	if errors.Is(err, storage.ErrAppNotFound) {
	//		return nil, status.Error(codes.NotFound, "app not found")
	//	}
	//	return nil, status.Error(codes.Internal, "internal server error")
	//}

	return &ssov1.RefreshTokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}, nil
}

// todo переделать
// LogoutAll endpoint cleans all cached and stored in db tokens
func (s *serverAPI) LogoutAll(
	ctx context.Context,
	req *ssov1.LogoutAllRequest,
) (*ssov1.LogoutAllResponse, error) {
	userID := req.GetUserId()
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	//token := req.GetToken()
	//
	//err := s.auth.CompleteLogout(ctx, userID, token)
	//if err != nil {
	//	if errors.Is(err, storage.ErrUserNotFound) {
	//		return nil, status.Error(codes.NotFound, "user not found")
	//	}
	//	return nil, status.Error(codes.Internal, "internal server error")
	//}
	return &ssov1.LogoutAllResponse{
		Message: "user successfully logged out",
	}, nil
}
