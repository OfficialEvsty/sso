package auth

import (
	"context"
	"errors"
	"fmt"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/auth"
	"sso/internal/services/session"
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
	auth auth.Auth
	s    session.Session
}

func Register(gRPC *grpc.Server, auth *auth.Auth) {
	ssov1.RegisterAuthServiceServer(gRPC, &serverAPI{auth: *auth})
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
	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "missing app id")
	}
	access, refresh, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		fmt.Print(err.Error())
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	return &ssov1.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
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

	userID, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "permission denied")
	}
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
			return nil, status.Error(codes.PermissionDenied, "refresh token expired")
		}
		if errors.Is(err, storage.ErrTokenInvalid) {
			return nil, status.Error(codes.PermissionDenied, "invalid refresh token")
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.PermissionDenied, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}

	access, refresh, err := s.auth.UpdateTokens(ctx, userToken, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return nil, status.Error(codes.InvalidArgument, "app not found")
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
			return nil, status.Error(codes.InvalidArgument, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &ssov1.LogoutAllResponse{
		Message: "user successfully logged out",
	}, nil
}
