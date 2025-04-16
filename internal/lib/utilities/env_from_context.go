package utilities

import (
	"context"
	"sso/internal/app/interceptors"
)

// EnvFromContext extracts env key from context
func EnvFromContext(ctx context.Context) string {
	if env, ok := ctx.Value(interceptors.EnvKey).(string); ok {
		return env
	}
	return "development" // default
}
