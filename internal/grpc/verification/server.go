package verification

import (
	"context"
	"encoding/base64"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"github.com/lestrrat-go/jwx/jwk"
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

// GetJwks returns list of public keys to verify token's signature on client side
func (v *verificationServer) GetJwks(ctx context.Context, req *ssov1.GetJwksRequest) (*ssov1.GetJwksResponse, error) {
	keySet, err := v.verification.GetJwks(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var jwks []*ssov1.Jwk
	for i := range keySet.Len() {
		key, ok := keySet.Get(i)
		if !ok {
			return nil, status.Error(codes.Internal, "key not found")
		}
		if rsaKey, ok := key.(jwk.RSAPublicKey); ok {
			// Base64URL-encode N (modulus) and E (exponent) without padding
			nBase64 := base64.RawURLEncoding.EncodeToString(rsaKey.N())
			eBase64 := base64.RawURLEncoding.EncodeToString(rsaKey.E())
			jwks = append(jwks, &ssov1.Jwk{
				Kty: key.KeyType().String(),
				Kid: key.KeyID(),
				Alg: key.Algorithm(),
				N:   nBase64,
				E:   eBase64,
			})
		}
	}
	resp := &ssov1.GetJwksResponse{
		Keys: jwks,
	}
	return resp, nil
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
