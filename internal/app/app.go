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
	"sso/internal/storage/repositories"
	"sso/internal/storage/repositories/cached"
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

	// cashed repositories
	sessionRepository := cached.NewSessionCachedRepository(storage.GetConnection(), cache.GetConnection())
	userScopeRepository := cached.NewUserScopeRepository(storage.GetConnection(), cache.GetConnection())
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
		sessionRepository,
		userScopeRepository,
		tokenTTL,
		refreshTTL,
		sessionTTL,
		authorizationCodeTTL,
		storage,
		repositories.NewIPRepository(storage.GetConnection()),
		repositories.NewPKCERepository(storage.GetConnection()),
		repositories.NewAuthCodeRepository(storage.GetConnection()),
	)
	sessionService := session.New(
		log,
		sessionRepository,
		cache,
		sessionEnabled,
	)

	accessService := access.New(
		log,
		userScopeRepository,
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
