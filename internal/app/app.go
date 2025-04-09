package app

import (
	"log/slog"
	"sso/internal/api/mail"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/config"
	"sso/internal/services/access"
	"sso/internal/services/auth"
	"sso/internal/services/session"
	"sso/internal/services/verification"
	"sso/internal/storage/cached_postgres"
	"sso/internal/storage/postgres"
	"sso/internal/storage/redis"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(
	log *slog.Logger,
	grpcPort int,
	redisConfig config.RedisConfig,
	storagePath string,
	sessionEnabled bool,
	useCache bool,
	tokenTTL time.Duration,
	refreshTTL time.Duration,
	sessionTTL time.Duration,
	authorizationCodeTTL time.Duration,
) *App {
	storage, err := postgres.New(storagePath)
	cache, err := redis.NewCache(&redisConfig, useCache)
	cashedStorage := cached_postgres.NewCachedStorage(storage, cache)
	mailService, err := mail.NewMailClient(log)
	if err != nil {
		panic(err)
	}
	authService := auth.New(
		log,
		storage,
		storage,
		storage,
		storage,
		cashedStorage,
		storage,
		storage,
		tokenTTL,
		refreshTTL,
		sessionTTL,
		authorizationCodeTTL,
	)
	sessionService := session.New(
		log,
		storage,
		cache,
		sessionEnabled,
	)

	accessService := access.New(
		log,
		storage,
		storage,
		storage,
		storage,
	)

	verificationService := verification.New(
		log,
		storage,
		cache,
		cache,
		storage,
	)

	grpcApp := grpcapp.New(log, authService, sessionService, accessService, verificationService, mailService, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
