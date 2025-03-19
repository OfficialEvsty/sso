package verification

import (
	"context"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/verification"
)

type verificationServer struct {
	ssov1.UnimplementedVerificationServiceServer
	verification verification.Verification
}

func Register(gRPC *grpc.Server, verification *verification.Verification) {
	ssov1.RegisterVerificationServiceServer(gRPC, &verificationServer{verification: *verification})
}

// SaveEmailToken handler
func (v *verificationServer) SaveEmailToken(ctx context.Context, req *ssov1.SaveEmailTokenRequest) (*ssov1.SaveEmailTokenResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Token is empty")
	}
	if req.GetEmail() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Email is empty")
	}
	err := v.verification.SaveEmailToken(ctx, req.GetEmail(), req.GetToken())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "save email token failed: %v", err)
	}
	return &ssov1.SaveEmailTokenResponse{
		Error:        false,
		ErrorMessage: "",
	}, nil
}

func (v *verificationServer) VerifyEmail(ctx context.Context, req *ssov1.VerifyEmailRequest) (*ssov1.VerifyEmailResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Token is empty")
	}
	err := v.verification.VerifyEmail(ctx, req.GetToken())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verify email failed: %v", err)
	}
	return &ssov1.VerifyEmailResponse{
		ErrorMessage: "",
		Error:        false,
		ErrorCode:    0,
	}, nil
}
