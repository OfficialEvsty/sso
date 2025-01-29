package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sso/internal/app"
	"sso/internal/config"
	"syscall"
)

const (
	envLocal = "local"
	envProd  = "prod"
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
		log,
		cfg.GRPC.Port,
		cfg.Redis,
		cfg.StoragePath,
		cfg.SessionEnabled,
		cfg.UseCache,
		cfg.TokenTTL,
		cfg.RefreshTokenTTL,
	)

	go application.GRPCSrv.MustRun()

	// TODO: запустить gRPC-сервер приложения
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	sign := <-stop
	application.GRPCSrv.Stop()
	log.Info("application stopped.", slog.String("signal", sign.String()))
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	}

	return log
}
