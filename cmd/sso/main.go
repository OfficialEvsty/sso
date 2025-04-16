package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/app/interceptors"
	"sso/internal/config"
	"syscall"
)

func main() {
	cfg := config.MustLoad()
	fmt.Printf("%#v\n", cfg)

	log := setupLogger(cfg.Env)

	log.Info("starting application...",
		slog.String("env", cfg.Env),
		slog.Any("cfg", cfg),
		slog.Int("port", cfg.GRPC.Port))

	application := app.New(
		cfg.Env,
		log,
		cfg.GRPC.Port,
		cfg.Redis,
		cfg.JWT,
		cfg.StoragePath,
		cfg.SessionEnabled,
		cfg.UseCache,
		cfg.TokenTTL,
		cfg.RefreshTokenTTL,
		cfg.SessionTTL,
		cfg.AuthorizationCodeTTL,
	)

	go application.GRPCSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	application.GRPCSrv.Stop()
	log.Info("application stopped.", slog.String("signal", sign.String()))
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case interceptors.EnvLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	case interceptors.EnvProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case interceptors.EnvDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	}

	return log
}
