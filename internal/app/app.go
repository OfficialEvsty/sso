package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"sso/internal/config"
	"sso/internal/services/auth"
	"sso/internal/services/session"
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
) *App {
	// TODO: инициализировать хранилище (storage)
	storage, err := postgres.New(storagePath)
	cache, err := redis.NewCache(&redisConfig, useCache)
	if err != nil {
		panic(err)
	}
	authService := auth.New(
		log,
		storage,
		storage,
		storage,
		storage,
		cache,
		tokenTTL,
		refreshTTL,
	)
	sessionService := session.New(
		log,
		cache,
		cache,
		sessionEnabled,
	)
	// TODO: init auth service (auth)
	grpcApp := grpcapp.New(log, authService, sessionService, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
