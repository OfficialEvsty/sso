package grpcapp

import (
	"fmt"
	"google.golang.org/grpc"
	"log/slog"
	"net"
	"sso/internal/api/mail"
	"sso/internal/app/interceptors"
	accessrpc "sso/internal/grpc/access"
	authrpc "sso/internal/grpc/auth"
	sessionrpc "sso/internal/grpc/session"
	verificationrpc "sso/internal/grpc/verification"
	"sso/internal/services/access"
	"sso/internal/services/auth"
	"sso/internal/services/session"
	"sso/internal/services/verification"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

// New creates new gRPC server app
func New(
	env string,
	log *slog.Logger,
	authService *auth.Auth,
	sessionService *session.Session,
	accessService *access.Access,
	verificationService *verification.Verification,
	mailService *mail.MailClient,
	port int,
) *App {
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		interceptors.EnvUnaryInterceptor(env),
		interceptors.MetadataInterceptor(log),
	))

	authrpc.Register(gRPCServer, authService, verificationService, mailService)
	sessionrpc.Register(gRPCServer, sessionService)
	accessrpc.Register(gRPCServer, accessService)
	verificationrpc.Register(gRPCServer, verificationService)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// MustRun runs gRPC server and panic if any occurs
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

// Run grpc server
func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(slog.String("op", op),
		slog.Int("port", a.port),
	)

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("starting gRPC server", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Stop grpc server
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("stopping gRPC server")
	a.gRPCServer.GracefulStop()
}
