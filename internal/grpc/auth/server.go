package auth

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log"
	"sso/internal/api/mail"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
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

// Authorize OAuth2.0 specification authorization method
// If user has the active session simplify redirects with authorization code
// Else creates initial session and redirects user on login page
// Throw error if faces unpredictably behaviour
func (s *serverAPI) Authorize(ctx context.Context, req *ssov1.AuthorizeRequest) (*ssov1.AuthorizeResponse, error) {
	if req.ClientId == "" {
		return nil, status.Error(codes.InvalidArgument, "missing client id")
	}
	if req.RedirectUri == "" {
		return nil, status.Error(codes.InvalidArgument, "missing redirect uri")
	}
	cc, err := uuid.Parse(req.GetCodeChallenge())
	if req.CodeChallenge == "" || err != nil {
		return nil, status.Error(codes.InvalidArgument, "missing code challenge")
	}
	if req.ResponseType == "" {
		return nil, status.Error(codes.InvalidArgument, "missing response type")
	}
	if req.State == "" {
		return nil, status.Error(codes.InvalidArgument, "missing state")
	}
	if req.CodeChallengeMethod == "" {
		return nil, status.Error(codes.InvalidArgument, "missing code challenge_method")
	}
	if req.Scope == "" {
		return nil, status.Error(codes.InvalidArgument, "missing scope")
	}

	pkce := &models.PKCE{
		CodeChallenge: cc,
		Method:        req.GetCodeChallengeMethod(),
	}
	code, err := s.auth.AuthorizeByCurrentSession(ctx, req.Scope, req.State, pkce)
	if err != nil {
		if errors.Is(err, storage.ErrNoMetadataContext) {
			return nil, status.Error(codes.InvalidArgument, "no metadata context by specified key")
		}
		if !errors.Is(err, storage.InfoUserUnauthenticated) {
			return nil, status.Error(codes.Internal, "internal server error while authorization by current session")
		}
		sessionID, loginUri, err := s.auth.AuthorizeByLogin(ctx, req)
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
				RedirectUri: req.RedirectUri,
				Code:        code.String(),
				State:       req.GetState(),
			},
		},
	}, nil
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
	access, refresh, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword())
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
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	// sending metadata pairs as headers
	md := metadata.Pairs("refresh-token", refresh)
	err = grpc.SendHeader(ctx, md)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to send header metadata")
	}

	//todo переделать
	return &ssov1.LoginResponse{
		RedirectUri: access,
		Code:        refresh,
		State:       "",
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

// RefreshToken handler updates user's tokens by receiving refresh token from user
func (s *serverAPI) RefreshToken(
	ctx context.Context,
	req *ssov1.RefreshTokenRequest,
) (*ssov1.RefreshTokenResponse, error) {
	userToken := req.GetRefreshToken()
	appID := req.GetAppId()
	if userToken == "" {
		return nil, status.Error(codes.InvalidArgument, "missing refresh token")
	}
	userID, err := s.auth.ValidateRefreshToken(ctx, userToken)

	if err != nil {
		if errors.Is(err, storage.ErrTokenExpired) {
			return nil, status.Error(codes.FailedPrecondition, "refresh token expired")
		}
		if errors.Is(err, storage.ErrTokenInvalid) {
			return nil, status.Error(codes.FailedPrecondition, "invalid refresh token")
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	access, refresh, err := s.auth.UpdateTokens(ctx, userToken, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return nil, status.Error(codes.NotFound, "app not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return &ssov1.RefreshTokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// LogoutAll endpoint cleans all cached and stored in db tokens
func (s *serverAPI) LogoutAll(
	ctx context.Context,
	req *ssov1.LogoutAllRequest,
) (*ssov1.LogoutAllResponse, error) {
	userID := req.GetUserId()
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	token := req.GetToken()

	err := s.auth.CompleteLogout(ctx, userID, token)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.LogoutAllResponse{
		Message: "user successfully logged out",
	}, nil
}
