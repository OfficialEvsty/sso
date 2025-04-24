package interceptors

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"log/slog"
)

// MetadataInterceptor debuggs key-value pairs from md
func MetadataInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		const op = "interceptors.MetadataInterceptor"
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}
		var metadataLog string
		for k, v := range md {
			metadataLog += fmt.Sprintf("%s: %s      ", k, v)
		}
		logger.With(slog.String("op", op)).Debug(metadataLog)
		return handler(ctx, req)
	}
}
