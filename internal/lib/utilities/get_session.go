package utilities

import (
	"context"
	"google.golang.org/grpc/metadata"
	"log/slog"
	"sso/internal/storage"
	"strconv"
	"strings"
)

// GetUserSession support func for extracting session id from metadata
func GetUserSession(ctx context.Context, logger *slog.Logger) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Error("error while receiving metadata from context", slog.String("metadata_keys", strconv.Itoa(md.Len())))
		return "", storage.ErrNoMetadataContext
	}
	// if gateway unsupported key session_cookie cause slice can be empty that throws panic
	cookies := md.Get("cookie")
	if len(cookies) == 0 {
		logger.Error("no cookies found in metadata, cause gateway problem with setup necessary session key")
		return "", storage.InfoSessionNotFound
	}
	cookieKey := "session="
	for _, cookie := range cookies {
		index := strings.Index(cookie, cookieKey)
		if index != -1 {
			return cookie[index+len(cookieKey):], nil
		}
	}
	logger.Info("user unauthenticated")
	return "", storage.InfoUserUnauthenticated
}
