package access

import (
	"context"
	"errors"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/access"
	"sso/internal/storage"
)

type accessServer struct {
	ssov1.UnimplementedAccessServiceServer
	access access.Access
}

func Register(s *grpc.Server, a *access.Access) {
	ssov1.RegisterAccessServiceServer(s, &accessServer{access: *a})
}

// AssignGroupRole Endpoint assigns role to user
func (a *accessServer) AssignGroupRole(ctx context.Context, req *ssov1.AssignGroupRoleRequest) (*ssov1.AssignGroupRoleResponse, error) {
	userID := req.GetUserId()
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	roleID := req.GetRoleId()
	if roleID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid role id")
	}

	result, err := a.access.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		if errors.Is(err, storage.InfoUserAlreadyHasRole) {
			return nil, status.Error(codes.AlreadyExists, err.Error())
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, storage.ErrRoleNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.AssignGroupRoleResponse{
		Result:  result,
		Message: "role successfully applied to specified user",
	}, nil
}

// RevokeGroupRole endpoint revokes role from user
func (a *accessServer) RevokeGroupRole(ctx context.Context, req *ssov1.RevokeGroupRoleRequest) (*ssov1.RevokeGroupRoleResponse, error) {
	userID := req.GetUserId()
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	roleID := req.GetRoleId()
	if roleID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid role id")
	}

	result, err := a.access.RevokeRoleFromUser(ctx, userID, roleID)
	if err != nil {
		if errors.Is(err, storage.InfoUserHasNoSpecifiedRole) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		if errors.Is(err, storage.ErrRoleNotFound) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &ssov1.RevokeGroupRoleResponse{
		Result:  result,
		Message: "role successfully revoked from specified user",
	}, nil
}
