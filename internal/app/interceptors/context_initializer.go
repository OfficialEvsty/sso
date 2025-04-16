package interceptors

import (
	"context"
	"google.golang.org/grpc"
)

const (
	EnvDev   = "dev"
	EnvLocal = "local"
	EnvProd  = "prod"
)

type contextKey string

const EnvKey contextKey = "env"

// EnvUnaryInterceptor middleware for initializing context by env key-value
func EnvUnaryInterceptor(env string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// adding env into context
		newCtx := context.WithValue(ctx, EnvKey, env)
		return handler(newCtx, req)
	}
}
