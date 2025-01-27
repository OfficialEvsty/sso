package suite

import (
	"context"
	ssov1 "github.com/OfficialEvsty/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"sso/internal/config"
	"strconv"
	"testing"
)

type Suite struct {
	*testing.T
	Cfg        config.Config
	AuthClient ssov1.AuthClient
}

// Ofc better to create new config for test-cases
const configPath = "./config/test_client.yaml"

// New creates new test suite
func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadPath(configPath)

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	// Адрес gRPC сервиса
	grpcAddress := net.JoinHostPort("localhost", strconv.Itoa(cfg.GRPC.Port))

	// Клиент для сервиса

	cc, err := grpc.DialContext(
		context.Background(),
		grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal("grpc server connection failed: %v", err)
	}

	authClient := ssov1.NewAuthClient(cc)

	return ctx, &Suite{
		T:          t,
		Cfg:        *cfg,
		AuthClient: authClient,
	}
}
