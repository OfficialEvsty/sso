package utilities

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log/slog"
	"sso/internal/storage"
	"strconv"
	"strings"
)

// GetClientIPFromMetadata supports func for extracting client ip from metadata
func GetClientIPFromMetadata(ctx context.Context, logger *slog.Logger) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Error("error while receiving metadata from context", slog.String("metadata_keys", strconv.Itoa(md.Len())))
		return "", storage.ErrNoMetadataContext
	}

	ips := md.Get("client_ip")
	if len(ips) == 0 {
		logger.Error("error while receiving metadata from context", slog.String("client_ip", "len 0"))
		return "", storage.ErrKeyNotFound
	}
	logger.Debug("successfully extracted client's ip: ", slog.String("client_ip", ips[0]))
	return strings.Split(ips[0], ",")[0], nil
}
