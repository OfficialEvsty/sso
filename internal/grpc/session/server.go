package session

import (
	"context"
	"errors"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/session"
	"sso/internal/storage"
)

type sessionAPI struct {
	ssov1.UnimplementedSessionServiceServer
	s session.Session
}

func Register(gRPC *grpc.Server, s *session.Session) {
	ssov1.RegisterSessionServiceServer(gRPC, &sessionAPI{s: *s})
}

// GetUserSessions returns all user's sessions authentificated in different apps
func (s *sessionAPI) GetUserSessions(
	ctx context.Context,
	req *ssov1.UserSessionsRequest,
) (*ssov1.UserSessionsResponse, error) {
	if !s.s.Enabled {
		return nil, status.Error(codes.Unavailable, "this module currently disabled")
	}
	userID := req.GetUserId()
	if userID <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	sessions, err := s.s.GetUserSessions(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "sessions not found")
		}
		return nil, status.Error(codes.Internal, "internal server error")
	}
	var responseSessions = make([]*ssov1.Session, 0)
	for _, session_ := range sessions {
		responseSessions = append(responseSessions, &ssov1.Session{
			IpAddress: session_.Ip,
			Device:    session_.Device,
			CreatedAt: session_.CreatedAt.Unix(),
		})
	}
	return &ssov1.UserSessionsResponse{
		Sessions: responseSessions,
	}, nil
}
