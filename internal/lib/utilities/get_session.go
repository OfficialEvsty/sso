package utilities

import (
	"context"
	"errors"
	"google.golang.org/grpc/metadata"
	"log/slog"
	"sso/internal/storage"
	"strconv"
)

// GetUserSession support func for extracting session id from metadata
func GetUserSession(ctx context.Context, logger *slog.Logger) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Error("error while receiving metadata from context", slog.String("metadata_keys", strconv.Itoa(md.Len())))
		return "", storage.ErrNoMetadataContext
	}
	// if gateway unsupported key session_cookie cause slice can be empty that throws panic
	sessionIDs := md.Get("session_cookie")
	if len(sessionIDs) == 0 {
		logger.Error("no session found in metadata, cause gateway problem with setup necessary session key")
		return "", errors.New("no session cookie found")
	}
	sessionID := sessionIDs[0]
	// if session haven't provided
	if sessionID == "" {
		logger.Error("user unauthenticated", slog.String("session_id", sessionID))
		return "", storage.InfoUserUnauthenticated
	}
	return sessionID, nil
}
